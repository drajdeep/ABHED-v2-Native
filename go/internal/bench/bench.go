// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// Package bench measures a running ABHED lab: resolver workloads, response sizes per
// signature encoding, and zone churn. Upstream traffic (resolver <-> authoritative) is read
// from the patched NSD statistics, so the numbers are exact and need no packet capture.
package bench

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"abhed/internal/lab"
	"abhed/internal/mtl"
	"abhed/internal/stats"
)

// ------------------------------------------------------------------ workload

// Workload generates a reproducible query mix: 80% A for Zipf-popular hosts, 10% NXDOMAIN
// (names that sort right after an existing host), 5% NODATA (AAAA), 5% other names.
type Workload struct {
	rng    *rand.Rand
	hosts  int
	zipf   *rand.Zipf
	perm   []int
	others [][2]string
}

func NewWorkload(hosts int, seed int64) *Workload {
	rng := rand.New(rand.NewSource(seed))
	w := &Workload{rng: rng, hosts: hosts, perm: rng.Perm(hosts)}
	if hosts > 1 {
		w.zipf = rand.NewZipf(rng, 1.01, 1, uint64(hosts-1))
	}
	w.others = [][2]string{{"www.iem.lab.", "A"}, {"mail.iem.lab.", "A"}, {"iem.lab.", "MX"},
		{"iem.lab.", "TXT"}, {"www.lab.", "A"}, {"iem.lab.", "NS"}}
	return w
}

func (w *Workload) host() string {
	i := 0
	if w.zipf != nil {
		i = int(w.zipf.Uint64())
	}
	return lab.HostName(w.perm[i] + 1)
}

// Next returns (name, type, class of query).
func (w *Workload) Next() (string, uint16, string) {
	x := w.rng.Float64()
	switch {
	case x < 0.80:
		return w.host(), dns.TypeA, "A"
	case x < 0.90:
		h := w.host()
		return strings.TrimSuffix(h, ".iem.lab.") + "x.iem.lab.", dns.TypeA, "NXDOMAIN"
	case x < 0.95:
		return w.host(), dns.TypeAAAA, "NODATA"
	}
	o := w.others[w.rng.Intn(len(w.others))]
	return o[0], dns.StringToType[o[1]], "other"
}

// ------------------------------------------------------------------ helpers

// Stub queries the validating resolver. AD in the query asks for the AD bit (RFC 6840).
func Stub(addr string, port int, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	m.AuthenticatedData = true
	m.SetEdns0(1232, false)
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 1232}
	t0 := time.Now()
	r, _, err := c.Exchange(m, net.JoinHostPort(addr, fmt.Sprint(port)))
	if err == nil && r.Truncated {
		c.Net = "tcp"
		r, _, err = c.Exchange(m, net.JoinHostPort(addr, fmt.Sprint(port)))
	}
	return r, time.Since(t0), err
}

// Raw sends a query and returns the exact response bytes as the server wrote them.
func Raw(addr string, port int, m *dns.Msg, tcp bool) ([]byte, error) {
	q, err := m.Pack()
	if err != nil {
		return nil, err
	}
	hp := net.JoinHostPort(addr, fmt.Sprint(port))
	if !tcp {
		conn, err := net.DialTimeout("udp", hp, 3*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		return buf[:n], err
	}
	conn, err := net.DialTimeout("tcp", hp, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(q)))
	if _, err := conn.Write(append(hdr, q...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr))
	_, err = io.ReadFull(conn, resp)
	return resp, err
}

func nsdStats(s *lab.Spec, reset bool) (stats.Counters, error) {
	total := stats.Counters{}
	cmd := "stats_noreset"
	if reset {
		cmd = "stats"
	}
	for _, srv := range s.Servers() {
		c, err := stats.Run(s.Bin("nsd-control"), "-c", s.NSDConf(srv.Name), cmd)
		if err != nil {
			return nil, err
		}
		total = stats.Add(total, c)
	}
	return total, nil
}

func unboundStats(s *lab.Spec) stats.Counters {
	c, err := stats.Run(s.Bin("unbound-control"), "-c", s.UnboundConf(), "stats_noreset")
	if err != nil {
		return stats.Counters{}
	}
	return c
}

// RestartResolver gives the next trial a cold resolver (empty caches and ladder cache).
func RestartResolver(labsh, dir string) error {
	out, err := exec.Command("bash", labsh, "restart-resolver", dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s restart-resolver: %v: %s", labsh, err, out)
	}
	return nil
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[int(math.Min(float64(len(s)-1), p*float64(len(s))))]
}

// MeanSD is reported for every per-trial quantity.
type MeanSD struct {
	Mean float64 `json:"mean"`
	SD   float64 `json:"sd"`
}

func meanSD(xs []float64) MeanSD {
	if len(xs) == 0 {
		return MeanSD{}
	}
	var m float64
	for _, x := range xs {
		m += x
	}
	m /= float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	if len(xs) > 1 {
		v /= float64(len(xs) - 1)
	}
	return MeanSD{m, math.Sqrt(v)}
}

// Save writes v as indented JSON.
func Save(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(v, "", " ")
	return os.WriteFile(path, b, 0o644)
}

// ------------------------------------------------------------------ resolver workload

// Trial is one cold-resolver run of the workload.
type Trial struct {
	Queries      int                `json:"queries"`
	Failures     int                `json:"failures"`
	NotValidated int                `json:"not_validated"`
	P50ms        float64            `json:"p50_ms"`
	P95ms        float64            `json:"p95_ms"`
	Upstream     map[string]float64 `json:"upstream"` // NSD counters, summed over the 3 servers
	Resolver     map[string]float64 `json:"resolver"` // selected Unbound counters
}

// WorkloadResult aggregates trials for one configuration.
type WorkloadResult struct {
	Config  string            `json:"config"`
	Label   string            `json:"label"`
	Spec    lab.Spec          `json:"spec"`
	Trials  []Trial           `json:"trials"`
	Summary map[string]MeanSD `json:"summary"`
}

var upstreamKeys = []string{"num.udp", "abhed.tcp.queries", "num.tcp", "num.truncated", "abhed.bytes.udp",
	"abhed.bytes.tcp", "abhed.mtl.full", "abhed.mtl.condensed", "abhed.mtl.compact", "abhed.mtl.dedup",
	"abhed.mtl.trimmed"}
var resolverKeys = []string{"total.num.queries", "total.num.cachehits", "num.answer.secure", "num.answer.bogus",
	"total.recursion.time.avg"}

// RunWorkload runs `trials` cold-resolver trials of `queries` queries against a running lab.
func RunWorkload(s *lab.Spec, config, label, labsh string, trials, queries int, seed int64) (*WorkloadResult, error) {
	res := &WorkloadResult{Config: config, Label: label, Spec: *s, Summary: map[string]MeanSD{}}
	for t := 0; t < trials; t++ {
		if err := RestartResolver(labsh, s.Dir); err != nil {
			return nil, err
		}
		if _, err := nsdStats(s, true); err != nil {
			return nil, err
		}
		w := NewWorkload(s.Hosts, seed+int64(t))
		tr := Trial{Queries: queries, Upstream: map[string]float64{}, Resolver: map[string]float64{}}
		var lat []float64
		for i := 0; i < queries; i++ {
			name, qt, _ := w.Next()
			r, d, err := Stub(s.ResolverAddr, s.Port, name, qt)
			if err != nil || r == nil || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
				tr.Failures++
				continue
			}
			if !r.AuthenticatedData {
				tr.NotValidated++
			}
			lat = append(lat, float64(d.Microseconds())/1000)
		}
		tr.P50ms, tr.P95ms = pct(lat, 0.5), pct(lat, 0.95)
		up, err := nsdStats(s, false)
		if err != nil {
			return nil, err
		}
		for _, k := range upstreamKeys {
			tr.Upstream[k] = up[k]
		}
		ub := unboundStats(s)
		for _, k := range resolverKeys {
			tr.Resolver[k] = ub[k]
		}
		res.Trials = append(res.Trials, tr)
	}
	collect := func(f func(Trial) float64) MeanSD {
		var xs []float64
		for _, t := range res.Trials {
			xs = append(xs, f(t))
		}
		return meanSD(xs)
	}
	for _, k := range upstreamKeys {
		k := k
		res.Summary[k] = collect(func(t Trial) float64 { return t.Upstream[k] })
	}
	res.Summary["bytes"] = collect(func(t Trial) float64 { return t.Upstream["abhed.bytes.udp"] + t.Upstream["abhed.bytes.tcp"] })
	res.Summary["round_trips"] = collect(func(t Trial) float64 {
		return t.Upstream["num.udp"] + t.Upstream["abhed.tcp.queries"] + t.Upstream["num.tcp"]
	})
	res.Summary["p50_ms"] = collect(func(t Trial) float64 { return t.P50ms })
	res.Summary["p95_ms"] = collect(func(t Trial) float64 { return t.P95ms })
	res.Summary["failures"] = collect(func(t Trial) float64 { return float64(t.Failures) })
	res.Summary["not_validated"] = collect(func(t Trial) float64 { return float64(t.NotValidated) })
	return res, nil
}

// ------------------------------------------------------------------ response sizes

// SizeRow is the size distribution of one answer class under one encoding.
type SizeRow struct {
	Encoding string         `json:"encoding"`
	Class    string         `json:"class"`
	Min      int            `json:"min"`
	Mean     float64        `json:"mean"`
	Max      int            `json:"max"`
	FitUDP   float64        `json:"fit_udp"` // share of responses <= 1232 bytes
	Types    map[string]int `json:"mtl_types"`
}

// SizesResult is the output of RunSizes for one zone configuration.
type SizesResult struct {
	Config string    `json:"config"`
	Label  string    `json:"label"`
	Spec   lab.Spec  `json:"spec"`
	Limit  int       `json:"limit"`
	Rows   []SizeRow `json:"rows"`
}

func ednsQuery(name string, qt uint16, opts []dns.EDNS0) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.RecursionDesired = false
	m.SetEdns0(1232, true)
	o := m.IsEdns0()
	o.Option = append(o.Option, opts...)
	return m
}

func local(code uint16, data []byte) *dns.EDNS0_LOCAL { return &dns.EDNS0_LOCAL{Code: code, Data: data} }

// tagOf fetches the current SigTag of zone from server addr (TCP, full signature).
func tagOf(addr string, port int, zone string) ([]byte, error) {
	b, err := Raw(addr, port, ednsQuery(zone, dns.TypeSOA, nil), true)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(b); err != nil {
		return nil, err
	}
	for _, rr := range r.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
			raw, err := decodeB64(sig.Signature)
			if err != nil {
				return nil, err
			}
			info, err := mtl.Parse(raw)
			if err != nil {
				return nil, err
			}
			return info.Tag(), nil
		}
	}
	return nil, fmt.Errorf("no MTL RRSIG for %s SOA", zone)
}

// RunSizes queries the authoritative servers directly and records exact response sizes
// for each answer class and each signature encoding the zone supports.
func RunSizes(s *lab.Spec, config, label string, samples int, optSigTag, optABHED uint16) (*SizesResult, error) {
	res := &SizesResult{Config: config, Label: label, Spec: *s, Limit: 1232}
	rng := rand.New(rand.NewSource(7))
	var names []string
	for i := 0; i < samples; i++ {
		names = append(names, lab.HostName(rng.Intn(s.Hosts)+1))
	}
	type class struct {
		name, addr, zone string
		qs               [][2]any
	}
	var a, nodata, nx, ref [][2]any
	for _, n := range names {
		a = append(a, [2]any{n, dns.TypeA})
		nodata = append(nodata, [2]any{n, dns.TypeAAAA})
		nx = append(nx, [2]any{strings.TrimSuffix(n, ".iem.lab.") + "x.iem.lab.", dns.TypeA})
	}
	for _, n := range names[:min(20, len(names))] {
		ref = append(ref, [2]any{n, dns.TypeA})
	}
	classes := []class{
		{"A (positive)", s.SLDAddr, "iem.lab.", a},
		{"NODATA", s.SLDAddr, "iem.lab.", nodata},
		{"NXDOMAIN", s.SLDAddr, "iem.lab.", nx},
		{"Referral + DS", s.TLDAddr, "lab.", ref},
		{"DNSKEY", s.SLDAddr, "iem.lab.", [][2]any{{"iem.lab.", dns.TypeDNSKEY}}},
	}
	encodings := []string{"no option"}
	if s.Mode == "mtl" {
		encodings = append(encodings, "SigTag probe (no ladder held)", "SigTag condensed", "SigTag + ABHED compact")
	}
	for _, enc := range encodings {
		for _, c := range classes {
			var opts []dns.EDNS0
			if enc != "no option" {
				var tag []byte
				if enc != "SigTag probe (no ladder held)" {
					t, err := tagOf(c.addr, s.Port, c.zone)
					if err != nil {
						return nil, err
					}
					tag = t
				}
				opts = append(opts, local(optSigTag, tag))
				if enc == "SigTag + ABHED compact" {
					opts = append(opts, local(optABHED, []byte{0x03}))
				}
			}
			row := SizeRow{Encoding: enc, Class: c.name, Min: math.MaxInt, Types: map[string]int{}}
			var sum, fit int
			for _, q := range c.qs {
				b, err := Raw(c.addr, s.Port, ednsQuery(q[0].(string), q[1].(uint16), opts), true)
				if err != nil {
					return nil, err
				}
				n := len(b)
				sum += n
				row.Min, row.Max = min(row.Min, n), max(row.Max, n)
				if n <= res.Limit {
					fit++
				}
				r := new(dns.Msg)
				if r.Unpack(b) == nil {
					for _, rr := range append(append([]dns.RR{}, r.Answer...), r.Ns...) {
						if sig, ok := rr.(*dns.RRSIG); ok {
							if raw, err := decodeB64(sig.Signature); err == nil && s.Mode == "mtl" {
								if info, err := mtl.Parse(raw); err == nil {
									row.Types[mtl.TypeName(info.Type)]++
								}
							}
						}
					}
				}
			}
			row.Mean = float64(sum) / float64(len(c.qs))
			row.FitUDP = float64(fit) / float64(len(c.qs))
			res.Rows = append(res.Rows, row)
		}
	}
	return res, nil
}

// ------------------------------------------------------------------ churn

// ChurnStep is one re-sign + query round.
type ChurnStep struct {
	Step     int                `json:"step"`
	Hosts    int                `json:"hosts"`
	SignMs   float64            `json:"sign_ms"`
	Failures int                `json:"failures"`
	Upstream map[string]float64 `json:"upstream"`
}

// ChurnResult is the output of RunChurn.
type ChurnResult struct {
	Config string      `json:"config"`
	Label  string      `json:"label"`
	Spec   lab.Spec    `json:"spec"`
	Alpha  int         `json:"alpha"`
	Rho    int         `json:"rho"`
	Steps  []ChurnStep `json:"steps"`
}

// RunChurn: `steps` times, add `alpha` hosts and re-sign iem.lab. (same key, same MTL
// series), reload NSD, then send `rho` queries for names the resolver has not asked before
// (30% of them added in the last three steps). One long-lived resolver throughout.
func RunChurn(s *lab.Spec, config, label, labsh string, steps, alpha, rho int) (*ChurnResult, error) {
	res := &ChurnResult{Config: config, Label: label, Spec: *s, Alpha: alpha, Rho: rho}
	if err := RestartResolver(labsh, s.Dir); err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(42))
	asked := map[string]bool{}
	pick := func(lo, hi int) string {
		for k := 0; k < 50; k++ {
			n := lab.HostName(lo + rng.Intn(hi-lo+1))
			if !asked[n] {
				asked[n] = true
				return n
			}
		}
		return lab.HostName(lo + rng.Intn(hi-lo+1))
	}
	base := s.Hosts
	for i := 0; i < rho; i++ { // warm-up: keys and first ladders
		Stub(s.ResolverAddr, s.Port, pick(1, base), dns.TypeA)
	}
	for st := 1; st <= steps; st++ {
		t0 := time.Now()
		if _, err := s.Grow(alpha); err != nil {
			return nil, err
		}
		if _, err := stats.Run(s.Bin("nsd-control"), "-c", s.NSDConf("iem"), "reload", "iem.lab."); err != nil {
			return nil, err
		}
		time.Sleep(300 * time.Millisecond)
		signMs := float64(time.Since(t0).Microseconds()) / 1000
		if _, err := nsdStats(s, true); err != nil {
			return nil, err
		}
		step := ChurnStep{Step: st, Hosts: s.Hosts, SignMs: signMs, Upstream: map[string]float64{}}
		recentLo := max(base+1, s.Hosts-3*alpha+1)
		for i := 0; i < rho; i++ {
			var n string
			if rng.Float64() < 0.3 {
				n = pick(recentLo, s.Hosts)
			} else {
				n = pick(1, s.Hosts)
			}
			r, _, err := Stub(s.ResolverAddr, s.Port, n, dns.TypeA)
			if err != nil || r == nil || r.Rcode != dns.RcodeSuccess || !r.AuthenticatedData {
				step.Failures++
			}
		}
		up, err := nsdStats(s, false)
		if err != nil {
			return nil, err
		}
		for _, k := range upstreamKeys {
			step.Upstream[k] = up[k]
		}
		res.Steps = append(res.Steps, step)
	}
	return res, nil
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
