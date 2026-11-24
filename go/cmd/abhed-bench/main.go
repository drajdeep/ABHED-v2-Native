// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// abhed-bench measures a running ABHED lab and builds the report.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"abhed/internal/bench"
	"abhed/internal/lab"
	"abhed/internal/report"
)

const usage = `abhed-bench - measure an ABHED lab

usage:
  abhed-bench workload --dir DIR --config NAME [--label TEXT] [--trials 5] [--queries 500] [--out results]
  abhed-bench sizes    --dir DIR --config NAME [--label TEXT] [--samples 200] [--out results]
  abhed-bench churn    --dir DIR --config NAME [--label TEXT] [--steps 20] [--alpha 10] [--rho 50] [--out results]
  abhed-bench report   [--out results] [--order cfg1,cfg2,...]

The lab must be running (deploy/lab.sh up DIR). workload and churn restart the resolver
through deploy/lab.sh (override with --lab-sh).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "lab", "lab directory")
	config := fs.String("config", "", "configuration name used in file names and tables")
	label := fs.String("label", "", "configuration label for tables (default: config)")
	out := fs.String("out", "results", "results directory")
	labsh := fs.String("lab-sh", defaultLabSh(), "path of deploy/lab.sh")
	trials := fs.Int("trials", 5, "workload: cold-resolver trials")
	queries := fs.Int("queries", 500, "workload: queries per trial")
	seed := fs.Int64("seed", 1000, "workload: seed of the first trial")
	samples := fs.Int("samples", 200, "sizes: names per answer class")
	steps := fs.Int("steps", 20, "churn: re-signing steps")
	alpha := fs.Int("alpha", 10, "churn: hosts added per step")
	rho := fs.Int("rho", 50, "churn: queries per step")
	order := fs.String("order", "", "report: comma-separated configuration order")
	optSigTag := fs.Uint("opt-sigtag", 65001, "EDNS option code for SigTag")
	optABHED := fs.Uint("opt-abhed", 65002, "EDNS option code for ABHED flags")
	fs.Parse(args)
	if *label == "" {
		*label = *config
	}
	var err error
	switch cmd {
	case "report":
		err = report.Build(*out, strings.Split(*order, ","))
		if err == nil {
			fmt.Println("wrote", filepath.Join(*out, "REPORT.md"))
		}
	case "workload", "sizes", "churn":
		if *config == "" {
			fmt.Fprintln(os.Stderr, "--config is required")
			os.Exit(2)
		}
		abs, _ := filepath.Abs(*dir)
		var s *lab.Spec
		s, err = lab.Load(abs)
		if err != nil {
			break
		}
		switch cmd {
		case "workload":
			var r *bench.WorkloadResult
			if r, err = bench.RunWorkload(s, *config, *label, *labsh, *trials, *queries, *seed); err == nil {
				err = bench.Save(filepath.Join(*out, "workload-"+*config+".json"), r)
				fmt.Printf("workload %-14s bytes %8.0f  udp %6.1f  tcp %6.1f  truncated %6.1f  failures %.0f  not-validated %.0f\n",
					*config, r.Summary["bytes"].Mean, r.Summary["num.udp"].Mean, r.Summary["abhed.tcp.queries"].Mean,
					r.Summary["num.truncated"].Mean, r.Summary["failures"].Mean, r.Summary["not_validated"].Mean)
			}
		case "sizes":
			var r *bench.SizesResult
			if r, err = bench.RunSizes(s, *config, *label, *samples, uint16(*optSigTag), uint16(*optABHED)); err == nil {
				err = bench.Save(filepath.Join(*out, "sizes-"+*config+".json"), r)
				for _, row := range r.Rows {
					fmt.Printf("sizes %-12s %-32s %-14s max %5d  fits %3.0f%%\n", *config, row.Encoding, row.Class, row.Max, row.FitUDP*100)
				}
			}
		case "churn":
			var r *bench.ChurnResult
			if r, err = bench.RunChurn(s, *config, *label, *labsh, *steps, *alpha, *rho); err == nil {
				err = bench.Save(filepath.Join(*out, "churn-"+*config+".json"), r)
				var tcp, by, fails float64
				for _, st := range r.Steps {
					tcp += st.Upstream["abhed.tcp.queries"]
					by += st.Upstream["abhed.bytes.udp"] + st.Upstream["abhed.bytes.tcp"]
					fails += float64(st.Failures)
				}
				q := float64(*steps * *rho)
				fmt.Printf("churn %-14s tcp/100q %5.1f  bytes/q %6.0f  failures %.0f\n", *config, tcp/q*100, by/q, fails)
			}
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "abhed-bench:", err)
		os.Exit(1)
	}
}

func defaultLabSh() string {
	if exe, err := os.Executable(); err == nil {
		for _, p := range []string{"../share/abhed/lab.sh", "../../deploy/lab.sh"} {
			c := filepath.Join(filepath.Dir(exe), p)
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return "deploy/lab.sh"
}
