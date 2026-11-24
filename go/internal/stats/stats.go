// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// Package stats reads nsd-control and unbound-control statistics.
package stats

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Counters is a flat name -> value map ("num.udp", "abhed.bytes.tcp", ...).
type Counters map[string]float64

// Run executes a control command (e.g. nsd-control -c conf stats_noreset) and parses
// "name=value" lines.
func Run(bin string, args ...string) (Counters, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	c := Counters{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			c[strings.TrimSpace(k)] = f
		}
	}
	return c, nil
}

// Add returns a + b.
func Add(a, b Counters) Counters {
	r := Counters{}
	for k, v := range a {
		r[k] += v
	}
	for k, v := range b {
		r[k] += v
	}
	return r
}

// Sub returns b - a (counters between two snapshots).
func Sub(a, b Counters) Counters {
	r := Counters{}
	for k, v := range b {
		r[k] = v - a[k]
	}
	return r
}

// Prometheus renders counters in the Prometheus text exposition format.
func Prometheus(prefix string, labels map[string]string, c Counters) string {
	var lb []string
	for k, v := range labels {
		lb = append(lb, fmt.Sprintf("%s=%q", k, v))
	}
	sort.Strings(lb)
	l := ""
	if len(lb) > 0 {
		l = "{" + strings.Join(lb, ",") + "}"
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		name := prefix + strings.NewReplacer(".", "_", "-", "_").Replace(k)
		fmt.Fprintf(&b, "%s%s %g\n", name, l, c[k])
	}
	return b.String()
}
