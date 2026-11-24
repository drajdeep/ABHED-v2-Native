// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// Package lab builds and maintains an ABHED lab: three zones (".", "lab.", "iem.lab.")
// signed child-first with the abhed C tools, served by patched NSD, resolved and
// validated by patched Unbound.
package lab

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.tmpl
var templates embed.FS

// Spec is the persistent description of a lab (lab.json).
type Spec struct {
	Dir          string `json:"dir"`
	Prefix       string `json:"prefix"`        // where build.sh installed the stack
	Mode         string `json:"mode"`          // ecdsa | mldsa44 | split | mtl
	Layout       string `json:"layout"`        // mtl only: csk | split
	Order        string `json:"order"`         // mtl only: hot-last | canonical
	Hosts        int    `json:"hosts"`         // hosts in iem.lab.
	Profile      string `json:"profile"`       // resolver: base | sigtag | abhed
	TCPUpstream  bool   `json:"tcp_upstream"`  // resolver sends every query over TCP
	Tuned        bool   `json:"tuned"`         // prefetch-key + target-fetch-policy 0
	ValidityDays int    `json:"validity_days"` //
	Serial       int64  `json:"serial"`
	RootAddr     string `json:"root_addr"`
	TLDAddr      string `json:"tld_addr"`
	SLDAddr      string `json:"sld_addr"`
	ResolverAddr string `json:"resolver_addr"`
	Port         int    `json:"port"`
	ControlPort  int    `json:"control_port"`
}

// Defaults fills unset fields.
func (s *Spec) Defaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	set(&s.Prefix, "/opt/abhed")
	set(&s.Mode, "mtl")
	set(&s.Profile, "abhed")
	set(&s.RootAddr, "127.0.53.10")
	set(&s.TLDAddr, "127.0.53.20")
	set(&s.SLDAddr, "127.0.53.30")
	set(&s.ResolverAddr, "127.0.53.53")
	if s.Mode == "mtl" {
		set(&s.Layout, "csk")
		set(&s.Order, "hot-last")
	}
	if s.Hosts == 0 {
		s.Hosts = 1000
	}
	if s.ValidityDays == 0 {
		s.ValidityDays = 14
	}
	if s.Port == 0 {
		s.Port = 53
	}
	if s.Serial == 0 {
		s.Serial = time.Now().Unix()
	}
}

// Validate checks the combination of options.
func (s *Spec) Validate() error {
	switch s.Mode {
	case "ecdsa", "mldsa44", "split":
	case "mtl":
		if s.Layout != "csk" && s.Layout != "split" {
			return fmt.Errorf("layout must be csk or split")
		}
		if s.Order != "hot-last" && s.Order != "canonical" {
			return fmt.Errorf("order must be hot-last or canonical")
		}
	default:
		return fmt.Errorf("unknown mode %q", s.Mode)
	}
	switch s.Profile {
	case "base", "sigtag", "abhed":
	default:
		return fmt.Errorf("unknown profile %q", s.Profile)
	}
	if s.Hosts < 1 {
		return fmt.Errorf("hosts must be >= 1")
	}
	return nil
}

// Path returns a path inside the lab directory.
func (s *Spec) Path(p ...string) string { return filepath.Join(append([]string{s.Dir}, p...)...) }

// Bin returns the path of an installed program.
func (s *Spec) Bin(name string) string {
	for _, d := range []string{"bin", "sbin"} {
		p := filepath.Join(s.Prefix, d, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

// Load reads lab.json from dir.
func Load(dir string) (*Spec, error) {
	b, err := os.ReadFile(filepath.Join(dir, "lab.json"))
	if err != nil {
		return nil, fmt.Errorf("%s is not a lab directory (run abhedctl init): %w", dir, err)
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	s.Dir = dir
	return &s, nil
}

// Save writes lab.json atomically.
func (s *Spec) Save() error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeAtomic(s.Path("lab.json"), b, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ------------------------------------------------------------------ zones

// HostName returns the owner name of host i in iem.lab.
func HostName(i int) string { return fmt.Sprintf("host%06d.iem.lab.", i) }

func soa(ns string, serial int64) string {
	return fmt.Sprintf("SOA %s hostmaster.iem.lab. %d 7200 3600 1209600 300", ns, serial)
}

func (s *Spec) zoneRoot() string {
	return fmt.Sprintf(`$ORIGIN .
$TTL 3600
. %s
. NS a.root-servers.lab.
lab. NS ns1.nic.lab.
a.root-servers.lab. A %s
ns1.nic.lab. A %s
`, soa("a.root-servers.lab.", s.Serial), s.RootAddr, s.TLDAddr)
}

func (s *Spec) zoneLab() string {
	return fmt.Sprintf(`$ORIGIN lab.
$TTL 3600
@ %s
@ NS ns1.nic.lab.
ns1.nic A %s
a.root-servers A %s
www A 10.20.0.80
iem NS ns1.iem.lab.
ns1.iem A %s
`, soa("ns1.nic.lab.", s.Serial), s.TLDAddr, s.RootAddr, s.SLDAddr)
}

func (s *Spec) zoneIem() string {
	var b strings.Builder
	fmt.Fprintf(&b, `$ORIGIN iem.lab.
$TTL 3600
@ %s
@ NS ns1
@ MX 10 mail
@ TXT "ABHED-v2 lab zone"
ns1 A %s
www A 10.53.0.80
mail A 10.53.0.25
`, soa("ns1.iem.lab.", s.Serial), s.SLDAddr)
	for i := 1; i <= s.Hosts; i++ {
		fmt.Fprintf(&b, "host%06d A 10.%d.%d.%d\n", i, 54+i/65536, (i/256)%256, i%256)
	}
	return b.String()
}

// ------------------------------------------------------------------ keys and signing

type zoneDef struct{ name, file, short string }

var zones = []zoneDef{{"iem.lab.", "iem.lab", "iem"}, {"lab.", "lab", "lab"}, {".", "root", "root"}}

// keyAlgs returns the (KSK, ZSK) algorithms for the mode; ZSK "" means CSK.
func (s *Spec) keyAlgs() (string, string) {
	switch s.Mode {
	case "ecdsa":
		return "ecdsap256", "ecdsap256"
	case "mldsa44":
		return "mldsa44", "mldsa44"
	case "split":
		return "mldsa44", "ecdsap256"
	}
	if s.Layout == "csk" {
		return "mtl", ""
	}
	return "mldsa44", "mtl"
}

func (s *Spec) run(name string, args ...string) (string, error) {
	cmd := exec.Command(s.Bin(name), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func (s *Spec) keys(z zoneDef, fresh bool) ([]string, error) {
	dir := s.Path("keys", z.file)
	if !fresh {
		m, _ := filepath.Glob(filepath.Join(dir, "*.key"))
		if len(m) > 0 {
			for i := range m {
				m[i] = strings.TrimSuffix(m[i], ".key")
			}
			return m, nil
		}
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ksk, zsk := s.keyAlgs()
	var out []string
	p, err := s.run("abhed-keygen", "-a", ksk, "-k", "-d", dir, z.name)
	if err != nil {
		return nil, err
	}
	out = append(out, p)
	if zsk != "" {
		p, err := s.run("abhed-keygen", "-a", zsk, "-d", dir, z.name)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// SignResult reports one zone signing run.
type SignResult struct {
	Zone   string `json:"zone"`
	Output string `json:"output"`
}

// Sign writes the unsigned zones and signs them child-first, publishing each DS in the
// parent and the root DS as the resolver's trust anchor. fresh=true generates new keys and
// starts new MTL series; fresh=false keeps keys and continues the series.
func (s *Spec) Sign(fresh bool) ([]SignResult, error) {
	for _, d := range []string{"zones", "keys", "state", "etc", "run"} {
		if err := os.MkdirAll(s.Path(d), 0o755); err != nil {
			return nil, err
		}
	}
	if fresh {
		os.RemoveAll(s.Path("state"))
		os.MkdirAll(s.Path("state"), 0o700)
	}
	unsigned := map[string]string{"iem.lab": s.zoneIem(), "lab": s.zoneLab(), "root": s.zoneRoot()}
	var res []SignResult
	childDS := ""
	for _, z := range zones {
		text := unsigned[z.file] + childDS
		in := s.Path("zones", z.file+".zone")
		if err := writeAtomic(in, []byte(text), 0o644); err != nil {
			return nil, err
		}
		keys, err := s.keys(z, fresh)
		if err != nil {
			return nil, err
		}
		args := []string{"-q", "-o", z.name, "-f", s.Path("zones", z.file+".signed"), "-s", s.Path("state"),
			"-e", fmt.Sprint(s.ValidityDays)}
		if s.Mode == "mtl" {
			args = append(args, "-l", s.Order)
		}
		for _, k := range keys {
			args = append(args, "-k", k)
		}
		args = append(args, in)
		if _, err := s.run("abhed-signzone", args...); err != nil {
			return nil, err
		}
		ds, err := os.ReadFile(s.Path("zones", z.file+".signed.ds"))
		if err != nil {
			return nil, err
		}
		childDS = string(ds)
		res = append(res, SignResult{Zone: z.name, Output: strings.TrimSpace(childDS)})
	}
	if err := writeAtomic(s.Path("etc", "trust-anchor.ds"), []byte(childDS), 0o644); err != nil {
		return nil, err
	}
	return res, s.Save()
}

// Grow adds hosts to iem.lab. and re-signs iem.lab. only, continuing its key and MTL series.
// The parent DS does not change, so lab. and . stay as they are.
func (s *Spec) Grow(add int) (string, error) {
	s.Hosts += add
	s.Serial++
	z := zones[0]
	in := s.Path("zones", z.file+".zone")
	if err := writeAtomic(in, []byte(s.zoneIem()), 0o644); err != nil {
		return "", err
	}
	keys, err := s.keys(z, false)
	if err != nil {
		return "", err
	}
	args := []string{"-o", z.name, "-f", s.Path("zones", z.file+".signed"), "-s", s.Path("state"),
		"-e", fmt.Sprint(s.ValidityDays)}
	if s.Mode == "mtl" {
		args = append(args, "-l", s.Order)
	}
	for _, k := range keys {
		args = append(args, "-k", k)
	}
	out, err := s.run("abhed-signzone", append(args, in)...)
	if err != nil {
		return "", err
	}
	return out, s.Save()
}

// ------------------------------------------------------------------ configuration

// Server is one NSD instance.
type Server struct{ Name, Zone, File, Addr string }

// Servers lists the three authoritative servers.
func (s *Spec) Servers() []Server {
	return []Server{
		{"root", ".", "root.signed", s.RootAddr},
		{"lab", "lab.", "lab.signed", s.TLDAddr},
		{"iem", "iem.lab.", "iem.lab.signed", s.SLDAddr},
	}
}

// NSDConf / UnboundConf are the paths of rendered configuration files.
func (s *Spec) NSDConf(name string) string { return s.Path("etc", "nsd-"+name+".conf") }
func (s *Spec) UnboundConf() string       { return s.Path("etc", "unbound.conf") }

// Render writes nsd-*.conf, unbound.conf and root.hints from the embedded templates.
func (s *Spec) Render() error {
	t, err := template.ParseFS(templates, "templates/*.tmpl")
	if err != nil {
		return err
	}
	for _, srv := range s.Servers() {
		var b bytes.Buffer
		if err := t.ExecuteTemplate(&b, "nsd.conf.tmpl", map[string]any{"S": s, "Srv": srv}); err != nil {
			return err
		}
		if err := writeAtomic(s.NSDConf(srv.Name), b.Bytes(), 0o644); err != nil {
			return err
		}
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "unbound.conf.tmpl", map[string]any{"S": s}); err != nil {
		return err
	}
	if err := writeAtomic(s.UnboundConf(), b.Bytes(), 0o644); err != nil {
		return err
	}
	hints := fmt.Sprintf(".\t3600000\tNS\ta.root-servers.lab.\na.root-servers.lab.\t3600000\tA\t%s\n", s.RootAddr)
	return writeAtomic(s.Path("etc", "root.hints"), []byte(hints), 0o644)
}
