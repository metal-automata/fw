package fw

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"slices"
	"strings"
	"time"

	bmclib "github.com/bmc-toolbox/bmclib/v2"
	"github.com/bmc-toolbox/bmclib/v2/constants"
	"github.com/bmc-toolbox/bmclib/v2/providers"
	"github.com/bmc-toolbox/common"
	"github.com/bombsimon/logrusr/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

const (
	// logoutTimeout is the time spent waiting when logging out of a bmc
	logoutTimeout = 1 * time.Minute

	// loginTimeout is the time spent waiting when logging in to a bmc
	loginTimeout = 1 * time.Minute

	// delayHostPowerStatusChange is the delay after the host has been power cycled or powered on
	// this delay ensures that any existing pending updates are applied and that the
	// the host Components are initialized properly before inventory and other actions are attempted.
	delayHostPowerStatusChange = 5 * time.Minute

	// delay after when the BMC was reset
	delayBMCReset = 5 * time.Minute

	// delay between polling the firmware install status
	delayPollStatus = 10 * time.Second

	// maxPollStatusAttempts is set based on how long the loop below should keep polling
	// for a finalized state before giving up
	//
	// 600 (maxAttempts) * 10s (delayPollInstallStatus) = 100 minutes (1.6hours)
	maxPollStatusAttempts = 600

	// maxVerifyAttempts is the number of times - after a firmware install this poller will spend
	// attempting to verify the installed firmware equals the expected.
	//
	// Multiple attempts to verify is required to allow the BMC time to have its information updated,
	// the Supermicro BMCs on X12SPO-NTFs, complete the update process, but take
	// a while to update the installed firmware information returned over redfish.
	//
	// 30 (maxVerifyAttempts) * 10 (delayPollStatus) = 300s (5 minutes)
	maxVerifyAttempts = 30
)

var (
	ErrInstalledFirmwareNotEqual = errors.New("installed Version does not match new")
)

// Installer provides the Install method to apply a firmware install.
type Installer struct {
	DryRun       bool
	BMCAddr      string
	Username     string
	Password     string
	Vendor       string
	Component    string
	Version      string
	FirmwareFile string

	client *bmclib.Client
	logger *slog.Logger
}

// Install runs the firmware install.
func (obj *Installer) Install(ctx context.Context) error {
	// when no logger is defined, we default to logging at debug level
	if obj.logger == nil {
		obj.logger = slog.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{
					Level: slog.LevelDebug,
				},
			),
		)
	}

	obj.logger = obj.logger.With(
		slog.String("Component", obj.Component),
		slog.String("want", obj.Version),
		slog.String("bmc", obj.BMCAddr),
		slog.Bool("DryRun", obj.DryRun),
	)

	slog.SetDefault(obj.logger)

	obj.client = newClient(obj.BMCAddr, obj.Username, obj.Password)

	if err := obj.client.Open(ctx); err != nil {
		return err
	}

	defer func() {
		// context not used here on purpose XXX: WHY?
		if err := obj.client.Close(context.Background()); err != nil {
			slog.Error("bmc connection close error", slog.Any("msg", err))
		}
	}()

	steps, err := obj.client.For(obj.Vendor).FirmwareInstallSteps(ctx, "bmc")
	if err != nil {
		return fmt.Errorf("failed to identify firmware install steps: %w", err)
	}

	bmcResetOnInstallFailure, bmcResetPostInstall := bmcResetParams(steps)
	hostPowerOffRequired := hostPowerOffRequired(steps)

	var taskID string
	for _, step := range steps {
		switch step {
		case constants.FirmwareInstallStepUpload:
			var errUpload error
			taskID, errUpload = obj.upload(ctx)
			if errUpload != nil {
				return fmt.Errorf("firmware upload error: %w", errUpload)
			}

		case constants.FirmwareInstallStepInstallUploaded:
			var errVerify error
			taskID, errVerify = obj.installUploaded(ctx, taskID)
			if err != nil {
				return fmt.Errorf("firmware install uploaded firmware error: %w", errVerify)
			}

		case constants.FirmwareInstallStepInstallStatus:
			if err := obj.installStatus(
				ctx,
				taskID,
				constants.FirmwareInstallStepInstallUploaded,
				bmcResetOnInstallFailure,
				bmcResetPostInstall,
				hostPowerOffRequired,
			); err != nil {
				return fmt.Errorf("firmware install uploaded firmware error: %w", err)
			}

		default:
			return fmt.Errorf("unhandled case: %v", step)
		}
	}

	return nil
}

func newHTTPClient() *http.Client {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}

	return &http.Client{
		Timeout: 30 * time.Minute,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			Dial: (&net.Dialer{
				Timeout:   180 * time.Second,
				KeepAlive: 180 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   180 * time.Second,
			ResponseHeaderTimeout: 600 * time.Second,
			IdleConnTimeout:       300 * time.Second,
		},
	}
}

// newClient initializes a bmclib client with the given credentials.
func newClient(BMCAddr, Username, Password string) *bmclib.Client {

	l := logrus.New()
	l.Level = logrus.DebugLevel
	logger := logrusr.New(l)

	bmcClient := bmclib.NewClient(
		BMCAddr,
		Username,
		Password,
		bmclib.WithLogger(logger),
		bmclib.WithHTTPClient(newHTTPClient()),
		bmclib.WithPerProviderTimeout(loginTimeout),
		bmclib.WithRedfishEtagMatchDisabled(true),
	)

	// include bmclib drivers that support firmware related actions
	bmcClient.Registry.Drivers = bmcClient.Registry.Supports(
		providers.FeatureFirmwareInstallSteps,
		providers.FeatureInventoryRead,
	)

	// bmcClient.Registry.PreferDriver("redfish", "vendorapi")

	return bmcClient
}

func (obj *Installer) reOpenConnection(ctx context.Context) error {
	// doesn't matter if the connection close fails here
	if err := obj.client.Close(ctx); err != nil {
		slog.Warn(
			"connection close error",
			slog.Any("msg", err),
		)
	}

	obj.client = newClient(obj.BMCAddr, obj.Username, obj.Password)
	return obj.client.Open(ctx)
}

// TODO: this needs to match Component hardware model as well - for drives, nics etc
func (obj *Installer) getVersion(ctx context.Context) (string, error) {
	inv, err := obj.client.PreferProvider(obj.Vendor).Inventory(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to collect device inventory: %w", err)
	}

	if inv.Vendor == "" || strings.ToLower(obj.Vendor) != strings.ToLower(inv.Vendor) {
		return "", fmt.Errorf("device vendor mismatch: '%s' != '%s'", inv.Vendor, obj.Vendor)
	}

	if inv.BMC == nil {
		return "", fmt.Errorf("bmc inventory nil")
	}

	if inv.BMC.Firmware == nil {
		return "", fmt.Errorf("bmc firmware inventory")
	}

	if inv.BMC.Firmware.Installed == "" {
		return "", fmt.Errorf("bmc firmware Version unknown")
	}

	return inv.BMC.Firmware.Installed, nil
}

func (obj *Installer) installedVersionEqual(ctx context.Context) error {
	version, err := obj.getVersion(ctx)
	if err != nil {
		return err
	}

	if version != obj.Version {
		slog.Debug(
			"installed Version does not match expected",
			slog.String("current", version),
		)

		return ErrInstalledFirmwareNotEqual
	}

	return nil
}

func (obj *Installer) upload(ctx context.Context) (string, error) {
	fh, err := os.Open(obj.FirmwareFile)
	if err != nil {
		return "", errors.New("failed to open firmware file: " + err.Error())
	}
	defer fh.Close()

	slog.Debug("uploading firmware")
	if obj.DryRun {
		return "", nil
	}

	uploadTaskID, err := obj.client.PreferProvider(obj.Vendor).FirmwareUpload(ctx, obj.Component, fh)
	if err != nil {
		return "", err
	}

	return uploadTaskID, nil
}

func (obj *Installer) installUploaded(ctx context.Context, uploadTaskID string) (string, error) {
	slog.Debug("install uploaded firmware")
	if obj.DryRun {
		return "", nil
	}

	verifyTaskId, err := obj.client.PreferProvider(obj.Vendor).FirmwareInstallUploaded(ctx, obj.Component, uploadTaskID)
	if err != nil {
		return "", err
	}

	return verifyTaskId, nil
}

func (obj *Installer) installStatus(
	ctx context.Context,
	prevTaskID string,
	prevTaskKind constants.FirmwareInstallStep,
	bmcResetOnInstallFailure,
	bmcResetPostInstall,
	hostPowerOffRequired bool,
) error {
	var hostPowerCycled bool

	// number of status queries attempted
	var attempts, verifyAttempts int

	var attemptErrors *multierror.Error

	// inventory is set when the loop below determines that
	// a new collection should be attempted.
	var inventory bool

	// helper func
	componentIsBMC := func(c string) bool {
		return strings.EqualFold(strings.ToUpper(c), common.SlugBMC)
	}

	startTS := time.Now()

	for {
		// increment attempts
		attempts++

		// delay if we're in the second or subsequent attempts
		if attempts > 0 {
			sleepContext(ctx, delayPollStatus)
		}

		// return when attempts exceed maxPollStatusAttempts
		if attempts >= maxPollStatusAttempts {
			attemptErrors = multierror.Append(attemptErrors, fmt.Errorf(
				"bmc query threshold attempts error",
				"%d attempts querying FirmwareTaskStatus(), elapsed: %s",
				attempts,
				time.Since(startTS).String(),
			))

			return attemptErrors
		}

		// TODO: break into its own method
		if inventory {
			verifyAttempts++
			slog.Debug("verifying firmware Version is installed")
			err := obj.installedVersionEqual(ctx)
			// nolint:errorlint // default case catches misc errors
			// TODO: use errors.Is
			switch err {
			case nil:
				slog.Debug("Installed firmware matches expected.")

				return nil

			case ErrInstalledFirmwareNotEqual:
				// if the BMC came online and is still running the previous Version
				// the install failed
				if componentIsBMC(obj.Component) && verifyAttempts >= maxVerifyAttempts {
					errInstall := errors.New("BMC failed to install expected firmware")
					return errInstall
				}

			default:
				// includes errors - ErrInstalledVersionUnknown, ErrComponentNotFound
				attemptErrors = multierror.Append(attemptErrors, err)
				slog.Warn(
					"inventory collection to verify Component firmware returned error",
					slog.String("elapsed", time.Since(startTS).String()),
					slog.String("attempts", fmt.Sprintf("attempt %d/%d", attempts, maxPollStatusAttempts)),
					slog.Any("err", err),
				)

			}

			continue
		}

		// query firmware install status
		state, status, err := obj.client.PreferProvider(obj.Vendor).FirmwareTaskStatus(
			ctx,
			prevTaskKind,
			obj.Component,
			prevTaskID,
			obj.Version,
		)

		slog.Debug(
			"firmware install status query",
			slog.String("elapsed", time.Since(startTS).String()),
			slog.String("attempts", fmt.Sprintf("attempt %d/%d", attempts, maxPollStatusAttempts)),
			slog.String("taskState", string(state)),
			slog.String("bmcTaskID", prevTaskID),
			slog.String("status", status),
		)

		// error check returns when maxPollStatusAttempts have been reached
		if err != nil {
			attemptErrors = multierror.Append(attemptErrors, err)

			// no implementations available.
			if strings.Contains(err.Error(), "no FirmwareTaskVerifier implementations found") {
				return fmt.Errorf(
					"firmware install support for Component not available: %w", err,
				)
			}

			// When BMCs are updating its own firmware, they can go unreachable
			// they apply the new firmware and in most cases the BMC task information is lost.
			//
			// And so if we get an error and its a BMC Component that was being updated, we wait for
			// the BMC to be available again and validate its firmware matches the one expected.
			if componentIsBMC(obj.Component) {
				slog.Debug(
					"BMC task status lookup returned error",
					slog.String("delay", delayBMCReset.String()),
					slog.String("taskState", string(state)),
					slog.String("bmcTaskID", prevTaskID),
					slog.String("status", status),
					slog.String("err", err.Error()),
				)

				inventory = true
			}

			continue
		}

		switch state {
		// continue polling when install is running
		case constants.FirmwareInstallInitializing, constants.FirmwareInstallQueued, constants.FirmwareInstallRunning:
			continue

		// record the unknown status as an error
		case constants.FirmwareInstallUnknown:
			err = errors.New("BMC firmware task status unknown")
			attemptErrors = multierror.Append(attemptErrors, err)

			continue

		// return when host power cycle is required
		case constants.PowerCycleHost:
			// host was power cycled for this action - wait around until the status is updated
			if hostPowerCycled {
				continue
			}

			// power cycle server and continue
			if err := obj.powerCycleServer(ctx); err != nil {
				return err
			}

			hostPowerCycled = true

			// reset attempts
			attempts = 0

			continue

		// return error when install fails
		case constants.FirmwareInstallFailed:
			var errMsg string
			if status == "" {
				errMsg = fmt.Sprintf(
					"install failed with errors, task ID: %s",
					prevTaskID,
				)
			} else {
				errMsg = fmt.Sprintf(
					"install failed with errors, task ID: %s, status: %s",
					prevTaskID,
					status,
				)
			}

			// A BMC reset is required if the BMC install fails - to get it out of flash mode
			if componentIsBMC(obj.Component) && bmcResetOnInstallFailure {
				if err := obj.resetBMC(ctx); err != nil {
					slog.Warn(
						"install failure required a BMC reset, reset returned error",
						slog.String("err", err.Error()),
					)
				}

				slog.Warn(
					"failed to reset BMC after BMC firmware install failure",
					slog.Any("err", err.Error()),
				)
			}

			return fmt.Errorf("firmware install failed: %s", errMsg)

		// return nil when install is complete
		case constants.FirmwareInstallComplete:
			// The BMC would reset itself and returning now would mean the next install fails,
			// wait until the BMC is available again and verify its on the expected Version.
			if componentIsBMC(obj.Component) {
				inventory = true
				// re-initialize the client to make sure we're not re-using old sessions.
				if err := obj.reOpenConnection(ctx); err != nil {
					slog.Error(
						"failed to re-open BMC connection",
						slog.String("bmc", obj.BMCAddr),
						slog.String("Component", obj.Component),
						slog.Any("err", err.Error()),
					)

					return err
				}

				if bmcResetPostInstall {
					if errBmcReset := obj.resetBMC(ctx); errBmcReset != nil {
						slog.Error(
							"install success required a BMC reset, reset returned error",
							slog.Any("err", err),
						)
					}

					slog.Debug(
						"BMC was reset for firwmare install",
					)
				}

				continue
			}

			return nil

		default:
			return errors.New("unknown state returned from bmc: " + string(state))
		}
	}
}

func (obj *Installer) resetBMC(ctx context.Context) error {
	slog.Info(
		"resetting BMC, adding delay for BMC to be ready",
		slog.String("delay", delayBMCReset.String()),
	)

	if obj.DryRun {
		return nil
	}

	if _, err := obj.client.ResetBMC(ctx, "GracefulRestart"); err != nil {
		return err
	}

	return sleepContext(ctx, delayBMCReset)
}

func (obj *Installer) powerCycleServer(ctx context.Context) error {
	slog.Info(
		"power cycling host for firmware install",
	)

	if obj.DryRun {
		return nil
	}

	if _, err := obj.client.SetPowerState(ctx, "cycle"); err != nil {
		return err
	}

	return nil
}

func hostPowerOffRequired(steps []constants.FirmwareInstallStep) bool {
	return slices.Contains(steps, constants.FirmwareInstallStepPowerOffHost)
}

func bmcResetParams(steps []constants.FirmwareInstallStep) (bmcResetOnInstallFailure, bmcResetPostInstall bool) {
	for _, step := range steps {
		switch step {
		case constants.FirmwareInstallStepResetBMCOnInstallFailure:
			bmcResetOnInstallFailure = true
		case constants.FirmwareInstallStepResetBMCPostInstall:
			bmcResetPostInstall = true
		}
	}

	return bmcResetOnInstallFailure, bmcResetPostInstall
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
