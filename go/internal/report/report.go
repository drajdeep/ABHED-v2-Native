// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// Package report turns benchmark JSON into results/REPORT.md and SVG figures.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"abhed/internal/bench"
)

// Chart colours (validated categorical palette, light surface).
var series = []string{"#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"}

const (
	ink     = "#0b0b0b"
	muted   = "#52514e"
	grid    = "#e4e3df"
	surface = "#fcfcfb"
)

func esc(s string) string { return html.EscapeString(s) }

// HBar draws a horizontal bar chart. Bars over `limit` (if > 0) use the second colour.
func HBar(title, note string, labels []string, values []float64, limit float64, unit string) string {
	const left, right, rowH, top = 290.0, 90.0, 30.0, 52.0
	w := 900.0
	h := top + rowH*float64(len(labels)) + 44
	maxV := limit
	for _, v := range values {
		maxV = math.Max(maxV, v)
	}
	if maxV == 0 {
		maxV = 1
	}
	scale := (w - left - right) / maxV
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" font-family="system-ui,sans-serif">`, w, h)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="%s"/>`, surface)
	fmt.Fprintf(&b, `<text x="16" y="28" font-size="16" fill="%s">%s</text>`, ink, esc(title))
	for i, l := range labels {
		y := top + rowH*float64(i)
		bw := math.Max(values[i]*scale, 1)
		col := series[0]
		if limit > 0 && values[i] > limit {
			col = series[1]
		}
		fmt.Fprintf(&b, `<text x="%.0f" y="%.1f" font-size="12" fill="%s" text-anchor="end">%s</text>`, left-10, y+15, muted, esc(l))
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.1f" width="%.1f" height="18" rx="3" fill="%s"><title>%s: %s %s</title></rect>`,
			left, y+3, bw, col, esc(l), fnum(values[i]), unit)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="12" fill="%s">%s</text>`, left+bw+6, y+16, ink, fnum(values[i]))
	}
	if limit > 0 {
		x := left + limit*scale
		fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="%.0f" y2="%.0f" stroke="%s" stroke-dasharray="4 4"/>`, x, x, top-6, h-40, ink)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.0f" font-size="11" fill="%s" text-anchor="middle">%s</text>`, x, top-10, muted, fnum(limit))
	}
	fmt.Fprintf(&b, `<text x="16" y="%.0f" font-size="11" fill="%s">%s</text></svg>`, h-14, muted, esc(note))
	return b.String()
}

// Lines draws one line per series over a shared x axis.
func Lines(title, note string, x []float64, names []string, ys [][]float64, ylabel string) string {
	const w, h, l, r, t, bm = 900.0, 380.0, 70.0, 170.0, 50.0, 60.0
	maxY, maxX := 0.0, x[len(x)-1]
	for _, s := range ys {
		for _, v := range s {
			maxY = math.Max(maxY, v)
		}
	}
	maxY = niceCeil(maxY)
	px := func(v float64) float64 { return l + (v-x[0])/(maxX-x[0]+1e-9)*(w-l-r) }
	py := func(v float64) float64 { return h - bm - v/maxY*(h-t-bm) }
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" font-family="system-ui,sans-serif">`, w, h)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="%s"/>`, surface)
	fmt.Fprintf(&b, `<text x="16" y="28" font-size="16" fill="%s">%s</text>`, ink, esc(title))
	for i := 0; i <= 4; i++ {
		v := maxY * float64(i) / 4
		fmt.Fprintf(&b, `<line x1="%.0f" x2="%.0f" y1="%.1f" y2="%.1f" stroke="%s"/>`, l, w-r, py(v), py(v), grid)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.1f" font-size="11" fill="%s" text-anchor="end">%s</text>`, l-6, py(v)+4, muted, fnum(v))
	}
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="11" fill="%s" text-anchor="middle">re-signing step</text>`, (l+w-r)/2, h-18, muted)
	fmt.Fprintf(&b, `<text x="16" y="44" font-size="11" fill="%s">%s</text>`, muted, esc(ylabel))
	for k, s := range ys {
		var pts []string
		for i, v := range s {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", px(x[i]), py(v)))
		}
		col := series[k%len(series)]
		fmt.Fprintf(&b, `<polyline fill="none" stroke="%s" stroke-width="2" points="%s"/>`, col, strings.Join(pts, " "))
		last := s[len(s)-1]
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="11" fill="%s">%s</text>`, px(x[len(x)-1])+8, py(last)+4, ink, esc(names[k]))
	}
	fmt.Fprintf(&b, `<text x="16" y="%.0f" font-size="11" fill="%s">%s</text></svg>`, h-4, muted, esc(note))
	return b.String()
}

func niceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if m*p >= v {
			return m * p
		}
	}
	return 10 * p
}

func fnum(v float64) string {
	switch {
	case v >= 10000:
		return addCommas(fmt.Sprintf("%.0f", v))
	case v >= 100:
		return fmt.Sprintf("%.0f", v)
	case v == math.Trunc(v):
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func addCommas(s string) string {
	n := len(s)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (n-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func pm(m bench.MeanSD, scale float64) string {
	return fmt.Sprintf("%s ± %s", fnum(m.Mean*scale), fnum(m.SD*scale))
}

func loadAll[T any](dir, pattern string) []T {
	files, _ := filepath.Glob(filepath.Join(dir, pattern))
	sort.Strings(files)
	var out []T
	for _, f := range files {
		var v T
		if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// Build writes REPORT.md and figures/ under dir from the JSON files in dir.
func Build(dir string, order []string) error {
	figs := filepath.Join(dir, "figures")
	if err := os.MkdirAll(figs, 0o755); err != nil {
		return err
	}
	rank := map[string]int{}
	for i, c := range order {
		rank[c] = i + 1
	}
	byRank := func(a, b string) bool {
		ra, rb := rank[a], rank[b]
		if ra == 0 {
			ra = 1000
		}
		if rb == 0 {
			rb = 1000
		}
		return ra < rb || (ra == rb && a < b)
	}
	var L []string
	add := func(s ...string) { L = append(L, s...) }
	add("# ABHED-v2 results", "",
		"Measured on the real stack: patched NSD 4.15.4 (authoritative) and patched Unbound 1.26.2 "+
			"(validating resolver) serving and validating `.` → `lab.` → `iem.lab.`.",
		"Upstream traffic is read from NSD's statistics (`nsd-control stats`), summed over the three servers.",
		"", "Generated "+time.Now().UTC().Format("2006-01-02 15:04 UTC")+" by `abhed-bench report`.", "")
	if b, err := os.ReadFile(filepath.Join(dir, "environment.txt")); err == nil {
		add("## Environment", "", "```", strings.TrimSpace(string(b)), "```", "")
	}

	sizes := loadAll[bench.SizesResult](dir, "sizes-*.json")
	sort.Slice(sizes, func(i, j int) bool { return byRank(sizes[i].Config, sizes[j].Config) })
	if len(sizes) > 0 {
		add("## Response size against the 1,232-byte UDP limit", "",
			"Exact bytes as the authoritative server writes them (TCP, so nothing is truncated). "+
				"Each cell: min / mean / max, and the share that fits in 1,232 bytes.", "")
		classes := []string{}
		seen := map[string]bool{}
		for _, r := range sizes[0].Rows {
			if !seen[r.Class] {
				seen[r.Class] = true
				classes = append(classes, r.Class)
			}
		}
		add("| Zone | Encoding | Hosts | "+strings.Join(classes, " | ")+" |", "|---|---|---|"+strings.Repeat("---|", len(classes)))
		var lbl []string
		var nxMax []float64
		for _, s := range sizes {
			encs := []string{}
			es := map[string]bool{}
			for _, r := range s.Rows {
				if !es[r.Encoding] {
					es[r.Encoding] = true
					encs = append(encs, r.Encoding)
				}
			}
			for _, e := range encs {
				var cells []string
				for _, c := range classes {
					for _, r := range s.Rows {
						if r.Encoding == e && r.Class == c {
							cells = append(cells, fmt.Sprintf("%d / %.0f / %d (%.0f%%)", r.Min, r.Mean, r.Max, r.FitUDP*100))
							if c == "NXDOMAIN" {
								lbl = append(lbl, s.Label+": "+e)
								nxMax = append(nxMax, float64(r.Max))
							}
						}
					}
				}
				add(fmt.Sprintf("| %s | %s | %d | %s |", s.Label, e, s.Spec.Hosts, strings.Join(cells, " | ")))
			}
		}
		os.WriteFile(filepath.Join(figs, "nxdomain_size.svg"), []byte(HBar(
			"Largest NXDOMAIN response, bytes", "Dashed line: 1,232-byte UDP limit. Orange: needs TCP.",
			lbl, nxMax, 1232, "bytes")), 0o644)
		add("", "![NXDOMAIN sizes](figures/nxdomain_size.svg)", "")
	}

	wl := loadAll[bench.WorkloadResult](dir, "workload-*.json")
	sort.Slice(wl, func(i, j int) bool { return byRank(wl[i].Config, wl[j].Config) })
	if len(wl) > 0 {
		w0 := wl[0]
		add("## Resolver workload", "",
			fmt.Sprintf("%d trials × %d queries, cold resolver per trial (Unbound restarted), different seed per trial. "+
				"Mix: 80%% A (Zipf-popular), 10%% NXDOMAIN, 5%% NODATA, 5%% other. Zone: %d hosts.",
				len(w0.Trials), w0.Trials[0].Queries, w0.Spec.Hosts),
			"Round trips = UDP queries + TCP queries + TCP connections.", "",
			"| Configuration | Bytes received by resolver (KiB) | UDP queries | TCP queries | Truncated | Round trips | MTL full / condensed / compact | Resolver p50 ms | Failures | Not validated |",
			"|---|---|---|---|---|---|---|---|---|---|")
		var lbl []string
		var by, tcp []float64
		for _, r := range wl {
			s := r.Summary
			add(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s / %s / %s | %s | %s | %s |", r.Label, pm(s["bytes"], 1.0/1024),
				pm(s["num.udp"], 1), pm(s["abhed.tcp.queries"], 1), pm(s["num.truncated"], 1), pm(s["round_trips"], 1),
				fnum(s["abhed.mtl.full"].Mean), fnum(s["abhed.mtl.condensed"].Mean), fnum(s["abhed.mtl.compact"].Mean),
				pm(s["p50_ms"], 1), fnum(s["failures"].Mean), fnum(s["not_validated"].Mean)))
			lbl = append(lbl, r.Label)
			by = append(by, s["bytes"].Mean/1024)
			tcp = append(tcp, s["abhed.tcp.queries"].Mean)
		}
		os.WriteFile(filepath.Join(figs, "workload_bytes.svg"), []byte(HBar("Bytes received by the resolver per trial, KiB",
			"Mean over trials. Lower is better.", lbl, by, 0, "KiB")), 0o644)
		os.WriteFile(filepath.Join(figs, "workload_tcp.svg"), []byte(HBar("Upstream TCP queries per trial",
			"Mean over trials. TCP is the fallback path; lower is better.", lbl, tcp, 0, "queries")), 0o644)
		add("", "![bytes](figures/workload_bytes.svg)", "", "![tcp](figures/workload_tcp.svg)", "")
	}

	ch := loadAll[bench.ChurnResult](dir, "churn-*.json")
	sort.Slice(ch, func(i, j int) bool { return byRank(ch[i].Config, ch[j].Config) })
	if len(ch) > 0 {
		c0 := ch[0]
		add("## Zone churn", "", fmt.Sprintf("Zone grows by %d hosts per step and is re-signed (same key, same MTL series); "+
			"NSD reloads; one long-lived resolver then asks %d names it has not asked before (30%% of them new). "+
			"%d steps.", c0.Alpha, c0.Rho, len(c0.Steps)), "",
			"| Configuration | TCP queries per 100 queries | Bytes per query | Re-sign + reload ms (mean) | Failures |", "|---|---|---|---|---|")
		var names []string
		var ys [][]float64
		var xs []float64
		for _, r := range ch {
			var tcp, by, ms, fails float64
			var y []float64
			for _, st := range r.Steps {
				tcp += st.Upstream["abhed.tcp.queries"]
				b := st.Upstream["abhed.bytes.udp"] + st.Upstream["abhed.bytes.tcp"]
				by += b
				ms += st.SignMs
				fails += float64(st.Failures)
				y = append(y, b/float64(r.Rho))
			}
			q := float64(len(r.Steps) * r.Rho)
			add(fmt.Sprintf("| %s | %.1f | %.0f | %.0f | %.0f |", r.Label, tcp/q*100, by/q, ms/float64(len(r.Steps)), fails))
			names = append(names, r.Config)
			ys = append(ys, y)
		}
		for i := range ch[0].Steps {
			xs = append(xs, float64(i+1))
		}
		os.WriteFile(filepath.Join(figs, "churn.svg"), []byte(Lines("Bytes received by the resolver per query while the zone changes",
			"One point per re-signing step.", xs, names, ys, "bytes per query")), 0o644)
		add("", "![churn](figures/churn.svg)", "")
	}
	return os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(strings.Join(L, "\n")+"\n"), 0o644)
}
