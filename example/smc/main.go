package smc

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/metal-automata/fw"
)

func main() {
	installer := &fw.Installer{
		//	DryRun:       true,
		BMCAddr:      "127.0.0.1",
		Component:    "bmc",
		Username:     "ADMIN",
		Password:     "hunter2",
		Vendor:       "supermicro",
		Version:      "1.72",
		FirmwareFile: "files/1.72/BMC_X11AST2400-3101MS_20240730_1.72_STDsp/BMC_X11AST2400-3101MS_20240730_1.72_STDsp.bin",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := installer.Connect(ctx); err != nil {
		slog.Error("connect error", slog.Any("msg", err))
		os.Exit(1)
	}
	defer func() {
		if err := installer.Close(context.Background()); err != nil {
			slog.Error("close error", slog.Any("msg", err))
		}
	}()

	if version, err := installer.GetVersion(ctx); err != nil {
		slog.Error("install error", slog.Any("msg", err))
		os.Exit(1)
	} else {
		slog.Info("version", slog.String("version", version))
	}

	if err := installer.Install(ctx); err != nil {
		slog.Error("install error", slog.Any("msg", err))
		os.Exit(1)
	}

	log.Println("done")
}
