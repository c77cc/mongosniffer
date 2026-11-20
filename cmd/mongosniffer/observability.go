package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c77cc/mongosniffer/capture"
	"github.com/c77cc/mongosniffer/model"
	"github.com/c77cc/mongosniffer/report"
)

const noTrafficWarningDelay = 10 * time.Second

type captureEventKind uint8

const (
	captureEventReady captureEventKind = iota
	captureEventTraffic
	captureEventOperation
	captureEventEncrypted
)

type runtimeServices struct {
	cancel   context.CancelFunc
	server   *http.Server
	listener net.Listener
	file     *os.File
	wg       sync.WaitGroup
	errors   chan error
}

func runCaptureWithStatus(parent context.Context, cfg config, servers []netip.AddrPort, collector *report.Collector, status io.Writer, warningDelay time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	services, err := startServices(ctx, cancel, cfg, collector)
	if err != nil {
		return err
	}
	events := make(chan captureEventKind, 16)
	notify := func(kind captureEventKind) {
		select {
		case events <- kind:
		default:
		}
	}
	onOperation := func(event model.OperationEvent) {
		if !event.Incomplete {
			notify(captureEventOperation)
		}
		if cfg.logCommands && event.RawCommand != "" {
			_, _ = fmt.Fprintf(status, "mongosniffer: command client=%s server=%s duration=%s command=%s\n", event.Metadata.ClientAddress, event.Metadata.ServerAddress, event.Duration, event.RawCommand)
		}
	}
	captureErrors := make(chan error, 1)
	go func() {
		captureErrors <- capture.Run(ctx, capture.Config{
			Interface: cfg.interfaceName, ReadPCAP: cfg.readPCAP, Servers: servers, Collector: collector,
			OnReady: func() { notify(captureEventReady) }, OnTraffic: func() { notify(captureEventTraffic) },
			OnOperation: onOperation, OnEncrypted: func() { notify(captureEventEncrypted) },
			RawCommand: cfg.logCommands || cfg.groupBy == "raw-command", GroupByRaw: cfg.groupBy == "raw-command",
		})
	}()

	var result error
	var warningTimer *time.Timer
	var warning <-chan time.Time
	ready, traffic, operation, encrypted := false, false, false, false
	handleEvent := func(kind captureEventKind) {
		switch kind {
		case captureEventReady:
			if ready {
				return
			}
			ready = true
			writeCaptureStarted(status, cfg, servers)
			if cfg.readPCAP == "" && warningDelay > 0 {
				warningTimer = time.NewTimer(warningDelay)
				warning = warningTimer.C
			}
		case captureEventTraffic:
			if !traffic {
				traffic = true
				_, _ = fmt.Fprintln(status, "mongosniffer: MongoDB traffic detected")
			}
		case captureEventOperation:
			if !operation {
				operation = true
				_, _ = fmt.Fprintln(status, "mongosniffer: MongoDB command capture is working")
				stopTimer(warningTimer)
				warning = nil
			}
		case captureEventEncrypted:
			if !encrypted {
				encrypted = true
				_, _ = fmt.Fprintln(status, "mongosniffer: encrypted MongoDB session detected; TLS commands cannot be decoded")
				stopTimer(warningTimer)
				warning = nil
			}
		}
	}

captureLoop:
	for {
		select {
		case kind := <-events:
			handleEvent(kind)
		case <-warning:
			for draining := true; draining; {
				select {
				case kind := <-events:
					handleEvent(kind)
				default:
					draining = false
				}
			}
			if !operation && !encrypted {
				writeCaptureWarning(status, warningDelay, traffic)
			}
			warning = nil
		case result = <-captureErrors:
			select {
			case serviceErr := <-services.errors:
				result = serviceErr
			default:
			}
			break captureLoop
		case result = <-services.errors:
			cancel()
			captureErr := <-captureErrors
			if result == nil {
				result = captureErr
			}
			break captureLoop
		case <-parent.Done():
			cancel()
			result = <-captureErrors
			break captureLoop
		}
	}
	stopTimer(warningTimer)
	for {
		select {
		case kind := <-events:
			handleEvent(kind)
		default:
			goto eventsDrained
		}
	}

eventsDrained:
	cancel()
	if closeErr := services.close(); result == nil {
		result = closeErr
	}
	if ready {
		writeCaptureStopped(status, collector)
	}
	return result
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func writeCaptureStarted(w io.Writer, cfg config, servers []netip.AddrPort) {
	if cfg.readPCAP != "" {
		_, _ = fmt.Fprintf(w, "mongosniffer: PCAP analysis started file=%q servers=%q\n", cfg.readPCAP, serverListString(servers))
		return
	}
	_, _ = fmt.Fprintf(w, "mongosniffer: capture started interface=%q servers=%q filter=%q\n", cfg.interfaceName, serverListString(servers), capture.ServerBPFFilter(servers))
	_, _ = fmt.Fprintln(w, "mongosniffer: waiting for MongoDB traffic; press Ctrl+C to stop and print the report")
}

func serverListString(servers []netip.AddrPort) string {
	values := make([]string, len(servers))
	for i, server := range servers {
		values[i] = server.String()
	}
	return strings.Join(values, ",")
}

func writeCaptureWarning(w io.Writer, delay time.Duration, traffic bool) {
	if traffic {
		_, _ = fmt.Fprintf(w, "mongosniffer: MongoDB traffic was detected, but no complete command was decoded after %s\n", delay)
		_, _ = fmt.Fprintln(w, "mongosniffer: capture may have started mid-connection, traffic may be TLS-encrypted, or the connection may use an unsupported opcode")
		return
	}
	_, _ = fmt.Fprintf(w, "mongosniffer: no matching MongoDB traffic detected after %s\n", delay)
	_, _ = fmt.Fprintln(w, "mongosniffer: check --interface, --server, active connections, and VM/container network routing")
}

func writeCaptureStopped(w io.Writer, collector *report.Collector) {
	snapshot := collector.Snapshot(currentBuild(), 0)
	var calls, incomplete, unacknowledged uint64
	for _, operation := range snapshot.Operations {
		calls += operation.Calls
		incomplete += operation.Incomplete
		unacknowledged += operation.Unacknowledged
	}
	drops := snapshot.Capture.KernelPacketsDropped + snapshot.Capture.InterfacePacketsDropped
	_, _ = fmt.Fprintf(w, "mongosniffer: capture stopped packets=%d matched=%d operations=%d incomplete=%d unacknowledged=%d encrypted_sessions=%d capture_drops=%d\n",
		snapshot.Capture.PacketsSeen, snapshot.Capture.PacketsMatched, calls, incomplete, unacknowledged, snapshot.EncryptedSessions, drops)
}

func startServices(ctx context.Context, cancel context.CancelFunc, cfg config, collector *report.Collector) (*runtimeServices, error) {
	s := &runtimeServices{cancel: cancel, errors: make(chan error, 1)}
	if cfg.listen != "" {
		listener, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen on %q: %w", cfg.listen, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok\n"))
		}))
		mux.HandleFunc("/report", getOnly(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = report.WriteJSON(w, collector.Snapshot(currentBuild(), cfg.maxGroups))
		}))
		mux.HandleFunc("/metrics", getOnly(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_ = report.WritePrometheus(w, collector.Snapshot(currentBuild(), 0))
		}))
		s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		s.listener = listener
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.fail(fmt.Errorf("serve observability HTTP: %w", err))
			}
		}()
	}
	if cfg.reportInterval > 0 {
		file, err := os.OpenFile(cfg.reportFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			_ = s.close()
			return nil, err
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = s.close()
			return nil, fmt.Errorf("secure report file %q: %w", cfg.reportFile, err)
		}
		s.file = file
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ticker := time.NewTicker(cfg.reportInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := report.WriteJSONLine(file, collector.Snapshot(currentBuild(), cfg.maxGroups)); err != nil {
						s.fail(fmt.Errorf("write periodic report: %w", err))
						return
					}
				}
			}
		}()
	}
	return s, nil
}
func (s *runtimeServices) fail(err error) {
	select {
	case s.errors <- err:
	default:
	}
	s.cancel()
}
func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}
func (s *runtimeServices) close() error {
	s.cancel()
	var result error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result = s.server.Shutdown(ctx)
		cancel()
		if errors.Is(result, http.ErrServerClosed) {
			result = nil
		}
	}
	s.wg.Wait()
	if s.file != nil {
		if err := s.file.Close(); result == nil {
			result = err
		}
	}
	return result
}
