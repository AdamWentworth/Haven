package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AdamWentworth/haven/internal/agent"
	"github.com/AdamWentworth/haven/internal/buildinfo"
	"github.com/AdamWentworth/haven/internal/collector"
	"github.com/AdamWentworth/haven/internal/diagnostic"
	"github.com/AdamWentworth/haven/internal/workload"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	command := "collect"
	arguments := os.Args[1:]
	if len(arguments) > 0 {
		command = arguments[0]
		arguments = arguments[1:]
	}
	if err := run(ctx, command, arguments); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, command string, arguments []string) error {
	switch command {
	case "doctor":
		flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
		jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: haven-agent doctor [--json]")
		}
		directory, err := agent.DefaultDirectory()
		if err != nil {
			return err
		}
		report := diagnostic.Agent(ctx, directory, defaultInstallation(), time.Now().UTC())
		if *jsonOutput {
			contents, err := diagnostic.JSON(report)
			if err != nil {
				return err
			}
			fmt.Println(string(contents))
		} else {
			fmt.Print(diagnostic.Text(report))
		}
		if report.Status == "not-ready" {
			return errors.New("HAVEN agent doctor found one or more failed checks")
		}
		return nil

	case "collect":
		return writeJSON(collector.NewForCurrentPlatform().Collect(ctx))

	case "export-docker-inventory":
		flags := flag.NewFlagSet("export-docker-inventory", flag.ContinueOnError)
		socketPath := flags.String("socket", "/var/run/docker.sock", "absolute Docker Engine socket path")
		outputPath := flags.String("output", "", "absolute sanitized inventory output path")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if *outputPath == "" {
			return errors.New("usage: haven-agent export-docker-inventory --output <absolute path> [--socket /var/run/docker.sock]")
		}
		inventory, err := workload.CollectDocker(ctx, *socketPath)
		if err != nil {
			return err
		}
		if err := workload.WriteFile(*outputPath, inventory); err != nil {
			return err
		}
		fmt.Printf("Recorded %d running Docker workload(s).\n", len(inventory.Workloads))
		return nil

	case "enroll":
		directory, err := agent.DefaultDirectory()
		if err != nil {
			return err
		}
		flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
		hubURL := flags.String("hub", "https://localhost:5443", "HAVEN agent endpoint")
		caPath := flags.String("ca", "", "trusted hub CA certificate")
		name := flags.String("name", "", "friendly device name")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		if *caPath == "" || *name == "" {
			return errors.New("usage: haven-agent enroll --hub https://localhost:5443 --ca <ca.crt> --name <device name>")
		}
		fmt.Fprint(os.Stderr, "Paste the one-time enrollment token, then press Enter: ")
		token, err := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Fprintln(os.Stderr)
		if err != nil && strings.TrimSpace(token) == "" {
			return fmt.Errorf("read enrollment token: %w", err)
		}
		config, err := agent.Enroll(ctx, directory, *hubURL, *name, strings.TrimSpace(token), *caPath)
		if err != nil {
			return err
		}
		fmt.Printf("Enrolled %s as %s.\n", config.DisplayName, config.DeviceID)
		return nil

	case "report":
		flags := flag.NewFlagSet("report", flag.ContinueOnError)
		installation := flags.String("installation", defaultInstallation(), "bounded installation kind reported to the hub")
		if err := flags.Parse(arguments); err != nil {
			return err
		}
		directory, err := agent.DefaultDirectory()
		if err != nil {
			return err
		}
		client, err := agent.Load(directory)
		if err != nil {
			return err
		}
		receipt, err := client.Report(ctx, collector.NewForCurrentPlatform().Collect(ctx), *installation)
		if err != nil {
			return err
		}
		fmt.Printf("Observation %s accepted at %s.\n", receipt.ObservationID, receipt.AcceptedAt.Local().Format("2006-01-02 15:04:05 MST"))
		return nil

	case "status":
		directory, err := agent.DefaultDirectory()
		if err != nil {
			return err
		}
		client, err := agent.Load(directory)
		if err != nil {
			return err
		}
		return writeJSON(struct {
			agent.Config
			Version  string `json:"version"`
			Revision string `json:"revision"`
		}{Config: client.Config(), Version: buildinfo.Version, Revision: buildinfo.Revision})
	case "version":
		return writeJSON(map[string]string{"version": buildinfo.Version, "revision": buildinfo.Revision})
	default:
		return errors.New("usage: haven-agent [collect | doctor | enroll | export-docker-inventory | report | status | version]")
	}
}

func defaultInstallation() string {
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd-user"
	}
	return buildinfo.AgentInstallation
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
