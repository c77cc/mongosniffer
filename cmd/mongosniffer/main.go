// Command mongosniffer passively analyzes MongoDB wire-protocol traffic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/c77cc/mongosniffer/capture"
	"github.com/c77cc/mongosniffer/report"
)

const maxOperationKeys = 10000
const maxServerEndpoints = 64

var releaseVersion string

type config struct {
	interfaceName, server, readPCAP, groupBy, listen, reportFile string
	maxGroups                                                    int
	logCommands, includeSystem, listInterfaces, version          bool
	reportInterval                                               time.Duration
}

type singleServerValue struct {
	value *string
	set   bool
}

func (v *singleServerValue) String() string {
	if v.value == nil {
		return ""
	}
	return *v.value
}

func (v *singleServerValue) Set(value string) error {
	if v.set {
		return fmt.Errorf("--server may only be specified once; separate endpoints with commas")
	}
	v.set = true
	*v.value = value
	return nil
}

func main() {
	if err := runMain(); err != nil {
		log.Printf("mongosniffer: %v", err)
		os.Exit(1)
	}
}
func runMain() error {
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.version {
		fmt.Println(buildVersion())
		return nil
	}
	if cfg.listInterfaces {
		return capture.PrintDevices(os.Stdout)
	}
	servers, err := validateConfig(cfg)
	if err != nil {
		return err
	}
	if cfg.groupBy == "raw-command" || cfg.logCommands {
		_, _ = fmt.Fprintln(os.Stderr, "mongosniffer: WARNING raw command output may contain sensitive business values")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collector := report.NewCollector(maxOperationKeys, cfg.includeSystem)
	err = runCaptureWithStatus(ctx, cfg, servers, collector, os.Stderr, noTrafficWarningDelay)
	if writeErr := report.WriteJSON(os.Stdout, collector.Snapshot(currentBuild(), cfg.maxGroups)); writeErr != nil {
		return writeErr
	}
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func parseFlags(args []string, output io.Writer) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("mongosniffer", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() { _, _ = fmt.Fprint(flags.Output(), usageText()) }
	flags.StringVar(&cfg.interfaceName, "interface", capture.DefaultInterface(), "network interface to capture")
	flags.Var(&singleServerValue{value: &cfg.server}, "server", "MongoDB endpoints as IP:PORT[,IP:PORT...] (required)")
	flags.BoolVar(&cfg.listInterfaces, "list-interfaces", false, "list capture interfaces and exit")
	flags.StringVar(&cfg.readPCAP, "read-pcap", "", "read a PCAP/PCAPNG file")
	flags.StringVar(&cfg.groupBy, "group-by", "fingerprint", "group by fingerprint or raw-command")
	flags.BoolVar(&cfg.logCommands, "log-commands", false, "log redacted original commands (sensitive)")
	flags.BoolVar(&cfg.includeSystem, "include-system-commands", false, "include safe control commands in operations")
	flags.IntVar(&cfg.maxGroups, "max-groups", 50, "maximum operation groups in reports (0 means all)")
	flags.StringVar(&cfg.listen, "listen", "", "HTTP address for /healthz, /report and /metrics")
	flags.DurationVar(&cfg.reportInterval, "report-interval", 0, "periodic JSONL report interval")
	flags.StringVar(&cfg.reportFile, "report-file", "", "periodic JSONL report file")
	flags.BoolVar(&cfg.version, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return cfg, nil
}

func usageText() string {
	return `Usage:
  mongosniffer --server IP:PORT[,IP:PORT...] [options]

Capture:
  --server IP:PORT[,IP:PORT...] MongoDB endpoints to observe
  --interface INTERFACE        live capture interface
  --list-interfaces            list interfaces and exit
  --read-pcap FILE             analyze PCAP/PCAPNG without live privileges

Output:
  --group-by fingerprint|raw-command
  --log-commands               log bounded redacted original commands (sensitive)
  --include-system-commands    include safe control command fingerprints
  --max-groups COUNT           report group limit; 0 means all

Observability:
  --listen ADDRESS             serve /healthz, /report and /metrics
  --report-interval DURATION   periodic JSONL interval
  --report-file FILE           periodic JSONL output (mode 0600)

Other:
  --version
  -h, --help
`
}

func validateConfig(cfg config) ([]netip.AddrPort, error) {
	if cfg.server == "" {
		return nil, fmt.Errorf("--server is required (for example 127.0.0.1:27017)")
	}
	servers, err := parseServerEndpoints(cfg.server)
	if err != nil {
		return nil, err
	}
	if cfg.readPCAP == "" && cfg.interfaceName == "" {
		return nil, fmt.Errorf("--interface is required for live capture; use --list-interfaces")
	}
	if cfg.maxGroups < 0 {
		return nil, fmt.Errorf("--max-groups cannot be negative")
	}
	if cfg.groupBy != "fingerprint" && cfg.groupBy != "raw-command" {
		return nil, fmt.Errorf("invalid --group-by %q", cfg.groupBy)
	}
	if cfg.reportInterval < 0 || cfg.reportInterval > 0 && cfg.reportFile == "" || cfg.reportFile != "" && cfg.reportInterval == 0 {
		return nil, fmt.Errorf("--report-file and positive --report-interval must be used together")
	}
	return servers, nil
}

func parseServerEndpoints(value string) ([]netip.AddrPort, error) {
	parts := strings.Split(value, ",")
	if len(parts) > maxServerEndpoints {
		return nil, fmt.Errorf("too many --server endpoints: got %d, maximum is %d", len(parts), maxServerEndpoints)
	}
	servers := make([]netip.AddrPort, 0, len(parts))
	seen := make(map[netip.AddrPort]struct{}, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid --server item %d: endpoint is empty", i+1)
		}
		server, err := netip.ParseAddrPort(part)
		if err != nil || server.Port() == 0 {
			return nil, fmt.Errorf("invalid --server item %d %q: expected IP:PORT", i+1, part)
		}
		server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
		if _, exists := seen[server]; exists {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	return servers, nil
}

func currentBuild() report.BuildInfo {
	build := report.BuildInfo{Version: releaseVersion}
	if info, ok := debug.ReadBuildInfo(); ok {
		if build.Version == "" {
			build.Version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				build.Revision = setting.Value
			}
		}
	}
	if build.Version == "" || build.Version == "(devel)" {
		build.Version = "devel"
	}
	return build
}
func buildVersion() string {
	build := currentBuild()
	if build.Revision != "" {
		return "mongosniffer " + build.Version + " " + build.Revision[:min(12, len(build.Revision))]
	}
	return "mongosniffer " + build.Version
}
