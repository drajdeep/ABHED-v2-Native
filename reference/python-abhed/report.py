# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Builds results/REPORT.md and results/figures/*.png from the raw benchmark JSON."""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from pathlib import Path

from . import __version__
from .params import ALG_MLDSA44, ALG_MTL, OPT_ABHED, OPT_SIGTAG, UDP_LIMIT

INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]


def environment(results) -> dict:
    def sh(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return ""
    import Crypto, cryptography, dns.version, oqs
    env = {"captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "abhed": __version__, "os": platform.platform(), "python": platform.python_version(),
           "cpu": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2") or platform.processor(),
           "cpus": os.cpu_count(), "liboqs": oqs.oqs_version(), "dnspython": dns.version.version,
           "pycryptodome": Crypto.__version__, "cryptography": cryptography.__version__,
           "git_commit": sh("git rev-parse --short HEAD") or "n/a",
           "alg_mldsa44": ALG_MLDSA44, "alg_mtl": ALG_MTL, "opt_sigtag": OPT_SIGTAG,
           "opt_abhed": OPT_ABHED, "udp_limit": UDP_LIMIT}
    Path(results).mkdir(parents=True, exist_ok=True)
    (Path(results) / "environment.json").write_text(json.dumps(env, indent=1))
    return env


def _load(results, name):
    p = Path(results) / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def _pm(d, scale=1.0, nd=1):
    return f"{d['mean']*scale:.{nd}f} ± {d['sd']*scale:.{nd}f}"


def _axes(ax, title):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=MUTED, length=0, labelsize=9)
    ax.set_title(title, loc="left", fontsize=11, color=INK, pad=12)


def _fig_udpfit(u, path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    classes = ["A (positive)", "NODATA", "NXDOMAIN", "Referral + DS"]
    encs = [e for e in dict.fromkeys(r["encoding"] for r in u["rows"]) if e != "ECDSA P-256"]
    fig, axs = plt.subplots(1, len(classes), figsize=(13, 3.6), sharey=True, facecolor=SURFACE)
    for ax, cls in zip(axs, classes):
        vals = [next(r["max"] for r in u["rows"] if r["encoding"] == e and r["cls"] == cls) for e in encs]
        ys = range(len(encs))[::-1]
        ax.barh(list(ys), vals, height=0.55, color=[SERIES[0] if v <= u["limit"] else SERIES[1] for v in vals])
        ax.axvline(u["limit"], color=INK, lw=1, ls=(0, (3, 3)))
        for y, v in zip(ys, vals):
            ax.text(max(v, u["limit"]) + 150, y, f"{v:,}", va="center", fontsize=8, color=INK)
        ax.set_yticks(list(ys)); ax.set_yticklabels(encs)
        ax.tick_params(labelleft=ax is axs[0])
        ax.set_xlim(0, max(9500, max(vals) * 1.25))
        _axes(ax, cls)
    fig.text(0.01, 0.01, f"Largest response in bytes. Dashed line: {u['limit']}-byte UDP limit. "
             "Blue fits in UDP, orange needs TCP.", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.05, 1, 1)); fig.savefig(path, dpi=150); plt.close(fig)


def _fig_bars(rows, key, title, note, path, scale=1.0, fmt="{:.0f}"):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8.5, 0.5 * len(rows) + 1.4), facecolor=SURFACE)
    vals = [(r[key]["mean"] if isinstance(r[key], dict) else r[key]) * scale for r in rows]
    ys = range(len(rows))[::-1]
    ax.barh(list(ys), vals, height=0.55, color=SERIES[0])
    for y, v in zip(ys, vals):
        ax.text(v + max(vals) * 0.01, y, fmt.format(v), va="center", fontsize=9, color=INK)
    ax.set_yticks(list(ys)); ax.set_yticklabels([r["label"] for r in rows])
    ax.set_xlim(0, max(vals) * 1.15 or 1)
    _axes(ax, title)
    fig.text(0.01, 0.01, note, fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.06, 1, 1)); fig.savefig(path, dpi=150); plt.close(fig)


def _fig_churn(c, path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8.5, 3.6), facecolor=SURFACE)
    for i, r in enumerate(c["rows"]):
        xs = [p["step"] for p in r["per_step"]]
        ys = [p["bytes_rx"] / c["rho"] for p in r["per_step"]]
        ax.plot(xs, ys, color=SERIES[i], lw=2, label=r["label"])
        ax.text(xs[-1] + 0.2, ys[-1], r["config"], fontsize=8, color=INK, va="center")
    ax.set_yscale("log"); ax.set_xlabel("re-signing step", color=MUTED, fontsize=9)
    ax.grid(axis="y", color=GRID, lw=0.6); ax.set_xlim(1, c["steps"] + 4)
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=2)
    _axes(ax, "Bytes received per query while the zone keeps changing (log scale)")
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def build(results):
    results = Path(results)
    figs = results / "figures"; figs.mkdir(parents=True, exist_ok=True)
    env = _load(results, "environment") or environment(results)
    L = ["# ABHED-v2 results report", "",
         "ML-DSA-44 versus ML-DSA-44 in Merkle Tree Ladder mode for DNSSEC, measured on a full "
         "chain of trust (root → `lab.` → `iem.lab.`) with a validating resolver.", "",
         "Everything here is regenerated by `./tb.sh bench-all`. Raw data is in the JSON files "
         "next to this report.", "", "## 1. Environment", "", "| Item | Value |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in env.items()]
    L += ["", "Configurations:", "", "| Name | Zone keys | Resolver behaviour |", "|---|---|---|",
          "| ecdsa | KSK 13 + ZSK 13 | UDP, TCP on TC |",
          "| split | KSK 18 (ML-DSA-44) + ZSK 13 | TCP for DNSKEY, UDP for data |",
          "| mldsa44 / mldsa44-tcp | KSK 18 + ZSK 18 | UDP then TCP / TCP first |",
          "| mtl-base / mtl-base-tcp | KSK 18 + ZSK MTL, canonical leaf order | no SigTag: every RRSIG is a full signature |",
          "| mtl-sigtag | same zone as mtl-base | SigTag option, condensed signatures (MTL-Type 0x02) |",
          "| mtl-abhed | one MTL CSK, hot-last leaf order | SigTag + ABHED option (path trimming, compact type 0xF1) |", ""]

    c = _load(results, "crypto")
    if c:
        p = c["primitives"]
        L += ["## 2. Signing and cold verification (zone iem.lab.)", "",
              f"Primitive costs on this machine: ML-DSA-44 sign {p['mldsa44_sign_us']:.0f} µs, verify "
              f"{p['mldsa44_verify_us']:.0f} µs; ECDSA P-256 sign {p['ecdsa_sign_us']:.0f} µs, verify "
              f"{p['ecdsa_verify_us']:.0f} µs; cSHAKE128 node hash through Python "
              f"{p['cshake128_python_us']:.2f} µs; SHAKE128 in C (hashlib) {p['shake128_native_us']:.2f} µs.", "",
              "| Dataset | Mode | RRSIGs | Sign ms | Cold verify-all ms | ML-DSA signs | ML-DSA verifies | Hashes (sign / verify) | Verify ms at C hash speed (estimate) | Stored signature bytes |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for r in c["rows"]:
            est = "-"
            if r["variant"] == "mtl":
                est = f"{(r['verify_hashes'] * p['shake128_native_us'] + r['mldsa_verifies'] * p['mldsa44_verify_us']) / 1000:.1f}"
            L.append(f"| {r['dataset']} | {r['variant']} | {r['rrsigs']} | {_pm(r['sign_ms'])} | {_pm(r['verify_ms'])} "
                     f"| {r['mldsa_signs']} | {r['mldsa_verifies']} | {r['sign_hashes']} / {r['verify_hashes']} | {est} | {r['stored_sig_bytes']:,} |")
        L += ["", "The MTL tree hashing is driven from Python (one interpreter call per node hash), "
              "ML-DSA-44 and ECDSA run in C. The measured MTL times are therefore an upper bound. "
              "All sign times also include building the canonical signing data in Python. "
              "The estimate column multiplies the counted hashes by the C hash cost; it is a "
              "calculation, not a measurement.", ""]

    n = 3
    for ds in ("small", "medium", "large", "xl"):
        u = _load(results, f"udpfit_{ds}")
        if not u:
            continue
        L += [f"## {n}. Response size against the {u['limit']}-byte UDP limit ({ds} zone)", "",
              "Size of the complete DNS response as the authoritative server builds it, for a "
              "resolver that already holds the zone's ladder (except the rows that say otherwise). "
              "Each cell is min / mean / max bytes and the share of responses that fit in UDP.", "",
              "| Encoding | " + " | ".join(dict.fromkeys(r["cls"] for r in u["rows"])) + " |",
              "|---|" + "---|" * len(set(r["cls"] for r in u["rows"]))]
        for e in dict.fromkeys(r["encoding"] for r in u["rows"]):
            cells = [f"{r['min']} / {r['mean']:.0f} / {r['max']} ({r['fit']*100:.0f}%)"
                     for r in u["rows"] if r["encoding"] == e]
            L.append(f"| {e} | " + " | ".join(cells) + " |")
        _fig_udpfit(u, figs / f"udpfit_{ds}.png")
        L += ["", f"![Response sizes]({'figures/udpfit_' + ds + '.png'})", ""]
        if ds == "large" and u.get("projection"):
            L += ["Calculated (not measured) worst-case NXDOMAIN response for larger zones, from the "
                  "encoding sizes and the fixed part measured above. One leaf per signed RRset; a zone "
                  "with NSEC has about two leaves per name.", "",
                  "| Leaves | Condensed, canonical leaf order | Condensed, hot-last | Compact, hot-last |",
                  "|---|---|---|---|"]
            for p in u["projection"]:
                cell = lambda v: f"{v}" + (" (over)" if v > u["limit"] else "")
                L.append(f"| 2^{p['k']} | {cell(p['condensed_canonical'])} | {cell(p['condensed_hot_last'])} | {cell(p['compact_hot_last'])} |")
            L.append("")
        n += 1

    for ds in ("small", "medium", "large", "xl"):
        d = _load(results, f"dns_{ds}")
        if not d:
            continue
        L += [f"## {n}. Resolver workload ({ds} zone, {d['queries']} queries × {d['trials']} trials, cold resolver per trial)", "",
              "80% A queries for Zipf-popular hosts, 10% NXDOMAIN, 5% NODATA, 5% other. Each trial uses "
              "a different seed. Counts are exchanges between the resolver and the authoritative servers. "
              "A round trip is one UDP exchange; a TCP exchange counts as two (handshake + query).", "",
              "| Configuration | Bytes received KiB | UDP exchanges | TCP exchanges | Truncated (TC) | Round trips | Upstream lookups answered without TCP | ML-DSA verifies | Crypto ms | Ladder cache bytes | Failures |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in d["rows"]:
            L.append(f"| {r['config']} | {_pm(r['bytes_rx'], 1/1024)} | {_pm(r['udp'])} | {_pm(r['tcp'])} | {_pm(r['tc'])} "
                     f"| {_pm(r['round_trips'])} | {r['udp_only_rate']['mean']*100:.1f}% | {_pm(r['mldsa_verifies'])} "
                     f"| {_pm(r['crypto_ms'])} | {r['ladder_bytes']['mean']:.0f} | {r['failures']} |")
        _fig_bars(d["rows"], "bytes_rx", f"Bytes received by the resolver per trial, KiB ({ds} zone)",
                  "Mean over trials. Lower is better.", figs / f"dns_bytes_{ds}.png", 1 / 1024, "{:.0f}")
        _fig_bars(d["rows"], "tcp", f"TCP exchanges per trial ({ds} zone)",
                  "Mean over trials. TCP is the fallback path; lower is better.", figs / f"dns_tcp_{ds}.png")
        L += ["", f"![bytes](figures/dns_bytes_{ds}.png)", "", f"![tcp](figures/dns_tcp_{ds}.png)", ""]
        n += 1

    d = _load(results, "dns_medium_live")
    if d:
        L += [f"## {n}. Latency over real sockets (medium zone, emulated RTT {d['rtt_ms']:.0f} ms per round trip)", "",
              "Same workload over loopback UDP/TCP sockets. The authoritative servers delay every "
              "reply by one RTT and every TCP accept by one more, so the cost of TCP is visible.", "",
              "| Configuration | p50 ms | p95 ms | TCP exchanges | Failures |", "|---|---|---|---|---|"]
        for r in d["rows"]:
            L.append(f"| {r['config']} | {_pm(r['p50_ms'])} | {_pm(r['p95_ms'])} | {_pm(r['tcp'])} | {r['failures']} |")
        L += [""]
        n += 1

    c = _load(results, "churn")
    if c:
        L += [f"## {n}. Zone churn", "",
              f"Zone of {c['hosts']} hosts. {c['steps']} times: {c['alpha']} hosts are added and the zone "
              f"is re-signed, then one long-lived resolver sends {c['rho']} queries (answer cache off; "
              "30% of the queries are for names added in the last three steps).", "",
              "| Configuration | TCP exchanges per 100 queries | Bytes received per query | Round trips per query | ML-DSA verifies per 100 queries | Failures |",
              "|---|---|---|---|---|---|"]
        for r in c["rows"]:
            L.append(f"| {r['config']} | {r['tcp_per_100q']:.1f} | {r['bytes_per_query']:.0f} | "
                     f"{r['round_trips_per_query']:.2f} | {r['mldsa_verifies_per_100q']:.1f} | {r['failures']} |")
        _fig_churn(c, figs / "churn.png")
        L += ["", "![churn](figures/churn.png)", ""]
    (results / "REPORT.md").write_text("\n".join(L) + "\n")
    print("wrote", results / "REPORT.md")
