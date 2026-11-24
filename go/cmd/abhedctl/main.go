// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// abhedctl prepares and maintains an ABHED lab: zones, keys, signing, configuration,
// re-signing, status and a Prometheus metrics endpoint.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"abhed/internal/lab"
	"abhed/internal/stats"
)

const usage = `abhedctl - ABHED-v2 lab control

usage:
  abhedctl init    --dir DIR [--mode mtl|mldsa44|split|ecdsa] [--layout csk|split]
                   [--order hot-last|canonical] [--hosts N] [--profile abhed|sigtag|base]
                   [--tcp-upstream] [--tuned=true] [--prefix /opt/abhed] [--port 53]
  abhedctl render  --dir DIR [--profile P] [--tcp-upstream=B] [--tuned=B]   rewrite configs only
  abhedctl grow    --dir DIR --add N        add hosts to iem.lab., re-sign (same series), reload NSD
  abhedctl resign  --dir DIR                re-sign all zones with the same keys and series
  abhedctl status  --dir DIR                lab description and server counters
  abhedctl metrics --dir DIR [--listen 127.0.0.1:9153]   Prometheus exporter
  abhedctl env     --dir DIR                shell variables for deploy/lab.sh
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "render":
		err = cmdRender(args)
	case "grow":
		err = cmdGrow(args)
	case "resign":
		err = cmdResign(args)
	case "status":
		err = cmdStatus(args)
	case "metrics":
		err = cmdMetrics(args)
	case "env":
		err = cmdEnv(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "abhedctl:", err)
		os.Exit(1)
	}
}

func dirFlag(fs *flag.FlagSet) *string { return fs.String("dir", "lab", "lab directory") }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := dirFlag(fs)
	s := lab.Spec{}
	fs.StringVar(&s.Prefix, "prefix", "/opt/abhed", "install prefix of the ABHED stack")
	fs.StringVar(&s.Mode, "mode", "mtl", "ecdsa | mldsa44 | split | mtl")
	fs.StringVar(&s.Layout, "layout", "", "mtl: csk (one MTL key) | split (ML-DSA-44 KSK + MTL ZSK)")
	fs.StringVar(&s.Order, "order", "", "mtl: hot-last | canonical leaf placement")
	fs.IntVar(&s.Hosts, "hosts", 1000, "hosts in iem.lab.")
	fs.StringVar(&s.Profile, "profile", "abhed", "resolver profile: base | sigtag | abhed")
	fs.BoolVar(&s.TCPUpstream, "tcp-upstream", false, "resolver uses TCP for every upstream query")
	fs.BoolVar(&s.Tuned, "tuned", true, "prefetch-key and target-fetch-policy 0 in unbound.conf")
	fs.IntVar(&s.Port, "port", 53, "DNS port for all servers")
	fs.StringVar(&s.RootAddr, "root-addr", "127.0.53.10", "")
	fs.StringVar(&s.TLDAddr, "tld-addr", "127.0.53.20", "")
	fs.StringVar(&s.SLDAddr, "sld-addr", "127.0.53.30", "")
	fs.StringVar(&s.ResolverAddr, "resolver-addr", "127.0.53.53", "")
	fs.Parse(args)
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	s.Dir = abs
	s.Defaults()
	if err := s.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	t0 := time.Now()
	res, err := s.Sign(true)
	if err != nil {
		return err
	}
	if err := s.Render(); err != nil {
		return err
	}
	fmt.Printf("lab %s: mode=%s layout=%s order=%s hosts=%d profile=%s (signed in %s)\n",
		s.Dir, s.Mode, s.Layout, s.Order, s.Hosts, s.Profile, time.Since(t0).Round(time.Millisecond))
	for _, r := range res {
		fmt.Printf("  DS %s\n", r.Output)
	}
	fmt.Printf("trust anchor: %s\nnext: deploy/lab.sh up %s\n", s.Path("etc", "trust-anchor.ds"), s.Dir)
	return nil
}

func load(args []string, name string, extra func(*flag.FlagSet)) (*lab.Spec, *flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dir := dirFlag(fs)
	if extra != nil {
		extra(fs)
	}
	fs.Parse(args)
	abs, _ := filepath.Abs(*dir)
	s, err := lab.Load(abs)
	return s, fs, err
}

func cmdRender(args []string) error {
	var profile string
	var tcp, tuned string
	s, _, err := load(args, "render", func(fs *flag.FlagSet) {
		fs.StringVar(&profile, "profile", "", "base | sigtag | abhed")
		fs.StringVar(&tcp, "tcp-upstream", "", "true | false")
		fs.StringVar(&tuned, "tuned", "", "true | false")
	})
	if err != nil {
		return err
	}
	if profile != "" {
		s.Profile = profile
	}
	if tcp != "" {
		s.TCPUpstream = tcp == "true"
	}
	if tuned != "" {
		s.Tuned = tuned == "true"
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if err := s.Render(); err != nil {
		return err
	}
	return s.Save()
}

func nsdControl(s *lab.Spec, name string, args ...string) (stats.Counters, error) {
	return stats.Run(s.Bin("nsd-control"), append([]string{"-c", s.NSDConf(name)}, args...)...)
}

func cmdGrow(args []string) error {
	var add int
	s, _, err := load(args, "grow", func(fs *flag.FlagSet) { fs.IntVar(&add, "add", 10, "hosts to add") })
	if err != nil {
		return err
	}
	out, err := s.Grow(add)
	if err != nil {
		return err
	}
	fmt.Println(out)
	if _, err := nsdControl(s, "iem", "reload", "iem.lab."); err != nil {
		fmt.Fprintln(os.Stderr, "note: NSD reload failed (is the lab running?):", err)
	}
	return nil
}

func cmdResign(args []string) error {
	s, _, err := load(args, "resign", nil)
	if err != nil {
		return err
	}
	s.Serial++
	if _, err := s.Sign(false); err != nil {
		return err
	}
	for _, srv := range s.Servers() {
		if _, err := nsdControl(s, srv.Name, "reload"); err != nil {
			fmt.Fprintln(os.Stderr, "note: reload failed for", srv.Name, err)
		}
	}
	return nil
}

func collect(s *lab.Spec) map[string]stats.Counters {
	out := map[string]stats.Counters{}
	for _, srv := range s.Servers() {
		if c, err := nsdControl(s, srv.Name, "stats_noreset"); err == nil {
			out["nsd_"+srv.Name] = c
		}
	}
	if c, err := stats.Run(s.Bin("unbound-control"), "-c", s.UnboundConf(), "stats_noreset"); err == nil {
		out["unbound"] = c
	}
	return out
}

var statusKeys = []string{"num.udp", "abhed.tcp.queries", "num.truncated", "abhed.bytes.udp",
	"abhed.bytes.tcp", "abhed.mtl.full", "abhed.mtl.condensed", "abhed.mtl.compact", "abhed.mtl.dedup",
	"abhed.mtl.trimmed", "total.num.queries", "total.num.cachehits", "num.answer.secure",
	"num.answer.bogus", "total.num.recursivereplies"}

func cmdStatus(args []string) error {
	s, _, err := load(args, "status", nil)
	if err != nil {
		return err
	}
	fmt.Printf("lab %s\n  mode=%s layout=%s order=%s hosts=%d profile=%s tcp-upstream=%v tuned=%v\n",
		s.Dir, s.Mode, s.Layout, s.Order, s.Hosts, s.Profile, s.TCPUpstream, s.Tuned)
	all := collect(s)
	if len(all) == 0 {
		fmt.Println("  no server answered: run deploy/lab.sh up", s.Dir)
		return nil
	}
	names := make([]string, 0, len(all))
	for k := range all {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		var parts []string
		for _, k := range statusKeys {
			if v, ok := all[n][k]; ok {
				parts = append(parts, fmt.Sprintf("%s=%g", k, v))
			}
		}
		fmt.Printf("  %-9s %s\n", n, strings.Join(parts, " "))
	}
	return nil
}

func cmdMetrics(args []string) error {
	var listen string
	s, _, err := load(args, "metrics", func(fs *flag.FlagSet) {
		fs.StringVar(&listen, "listen", "127.0.0.1:9153", "listen address")
	})
	if err != nil {
		return err
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for name, c := range collect(s) {
			fmt.Fprint(w, stats.Prometheus("abhed_", map[string]string{"server": name, "mode": s.Mode,
				"profile": s.Profile}, c))
		}
	})
	fmt.Printf("serving Prometheus metrics on http://%s/metrics\n", listen)
	return http.ListenAndServe(listen, nil)
}

func cmdEnv(args []string) error {
	s, _, err := load(args, "env", nil)
	if err != nil {
		return err
	}
	q := func(k, v string) { fmt.Printf("%s=%q\n", k, v) }
	q("ABHED_DIR", s.Dir)
	q("ABHED_PREFIX", s.Prefix)
	q("NSD", s.Bin("nsd"))
	q("NSD_CONTROL", s.Bin("nsd-control"))
	q("UNBOUND", s.Bin("unbound"))
	q("UNBOUND_CONTROL", s.Bin("unbound-control"))
	q("RESOLVER_ADDR", s.ResolverAddr)
	q("PORT", fmt.Sprint(s.Port))
	var names []string
	for _, srv := range s.Servers() {
		names = append(names, srv.Name)
		q("ADDR_"+strings.ToUpper(srv.Name), srv.Addr)
	}
	q("SERVERS", strings.Join(names, " "))
	return nil
}
