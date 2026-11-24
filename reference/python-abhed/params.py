# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Code points and limits. Everything that is not IANA-assigned is overridable by env var."""
import os

ALG_ECDSAP256 = 13
ALG_MLDSA44 = 18            # IANA-assigned (draft-westerbaan-dnssec-mldsa)
# ML-DSA-44-MTL-SHAKE-128 is "TBD" in draft-kaizer-dnsop-ml-dsa-mtl-dnssec. 244 is the first
# value of the Private Use range proposed by draft-johani-dnsop-dnssec-alg-experimental-range.
ALG_MTL = int(os.environ.get("ABHED_ALG_MTL", "244"))
ALG_NAMES = {ALG_ECDSAP256: "ECDSAP256SHA256", ALG_MLDSA44: "ML-DSA-44",
             ALG_MTL: "ML-DSA-44-MTL-SHAKE-128"}

# EDNS(0) option codes. The SigTag option code is "TBD" in the SigTag draft, so both
# values come from the Local/Experimental Use range 65001-65534 (RFC 6891).
OPT_SIGTAG = int(os.environ.get("ABHED_OPT_SIGTAG", "65001"))
OPT_ABHED = int(os.environ.get("ABHED_OPT_ABHED", "65002"))
ABHED_F_TRIM = 0x01         # server may trim the path to the rung of the client's ladder
ABHED_F_COMPACT = 0x02      # server may use the compact private MTL-Type 0xF1
MAX_SIGTAGS = 8

UDP_LIMIT = int(os.environ.get("ABHED_UDP_LIMIT", "1232"))
TTL = 3600
SIG_VALIDITY = 14 * 86400
MLDSA_CTX = os.environ.get("ABHED_MLDSA_CTX", "").encode()   # drafts use the empty context

ROOT_IP = os.environ.get("ROOT_IP", "172.31.53.10")
TLD_IP = os.environ.get("TLD_IP", "172.31.53.20")
SLD_IP = os.environ.get("SLD_IP", "172.31.53.30")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "172.31.53.53")
ROOT_NS, TLD_NS, SLD_NS = "a.root-servers.lab.", "ns1.nic.lab.", "ns1.iem.lab."
DATASETS = {"small": 100, "medium": 1000, "large": 10000, "xl": 100000}
