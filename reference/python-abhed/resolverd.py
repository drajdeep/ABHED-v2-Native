# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Stub-facing front end for abhed.resolver: lets dig / any stub query the validating resolver.
Sets AD=1 on validated answers and answers SERVFAIL when validation fails."""
from __future__ import annotations

import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rcode

from .authd import _recvn
from .resolver import Resolver


def answer(res: Resolver, lock, wire: bytes, tcp: bool):
    try:
        q = dns.message.from_wire(wire)
        question = q.question[0]
    except Exception:
        return None
    r = dns.message.make_response(q, recursion_available=True, our_payload=1232)
    do = q.edns >= 0 and bool(q.ednsflags & dns.flags.DO)
    try:
        with lock:
            out = res.resolve(question.name, question.rdtype)
        r.set_rcode(dns.rcode.from_text(out["rcode"]))
        r.flags |= dns.flags.AD
        msg = out["message"]
        r.answer = [x for x in msg.answer if do or x.rdtype != 46]
        r.authority = [x for x in msg.authority if do or x.rdtype not in (46, 47)]
    except Exception as e:                                   # Bogus or transport failure
        print(f"SERVFAIL {question.name}: {e}", flush=True)
        r.set_rcode(dns.rcode.SERVFAIL)
    data = r.to_wire(max_size=65535)
    if not tcp and len(data) > (q.payload if q.edns >= 0 else 512):
        t = dns.message.make_response(q, recursion_available=True, our_payload=1232)
        t.flags |= dns.flags.TC
        data = t.to_wire()
    return data


def serve(res: Resolver, host: str, port: int):
    lock = threading.Lock()

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            out = answer(res, lock, data, False)
            if out:
                sock.sendto(out, self.client_address)

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.settimeout(10)
            try:
                while True:
                    hdr = _recvn(s, 2)
                    if not hdr:
                        return
                    out = answer(res, lock, _recvn(s, struct.unpack(">H", hdr)[0]), True)
                    if not out:
                        return
                    s.sendall(struct.pack(">H", len(out)) + out)
            except (OSError, struct.error):
                return

    socketserver.ThreadingUDPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    u = socketserver.ThreadingUDPServer((host, port), UDP)
    t = socketserver.ThreadingTCPServer((host, port), TCP)
    for srv in (u, t):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return u, t
