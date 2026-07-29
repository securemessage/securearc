"""Minimal authoritative DNS server answering the TXT records one ARC scenario needs.

Exists so the ValiMail suite can be driven against securearc without touching the
real internet and without changing a line of production code: each scenario's
`txt-records` block is served here, and `securearc-check -n 127.0.0.1 -p <port>`
points the daemon's own resolver at it. The resolver under test is therefore the
real one, so record joining and negative answers are exercised too.

TXT only, deliberately. The SPF conformance harness in `securespf/test/rfc7208/`
has a fuller server because RFC 7208 needs A, AAAA, MX, PTR, CNAME and the type-99
SPF record. ARC key lookups are a single TXT query for
`<selector>._domainkey.<domain>`, and a purpose-built ~100 lines is easier to
verify by eye than a general server used at a tenth of its range. The two are not
shared because securespf and securearc are separate repositories and a test helper
is not worth a package.
"""

import socket
import struct
import threading

TYPE_TXT = 16
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


def _encode_name(name):
    """Encode a dotted name as DNS labels."""
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _decode_name(data, offset):
    """Decode a DNS name, following compression pointers. Returns (name, next_offset)."""
    labels = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _txt_rdata(value):
    """A TXT rdata field: one or more length-prefixed strings, each <= 255 bytes.

    Splitting at 255 is required by the wire format, not an optimisation. DKIM and
    ARC public keys are routinely longer than that, so every key in this suite
    takes the multi-string path -- which is also the path that exercises whether
    the resolver rejoins the strings rather than reading only the first.
    """
    raw = value.encode("utf-8")
    chunks = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


class TxtDns:
    """Serves a dict of {name: txt_value} on a UDP port, as a context manager."""

    def __init__(self, records, port, verbose=False):
        # Keys are lowercased: DNS names are case-insensitive, and the suite's
        # records and the queries securearc emits do not always agree on case.
        self.records = {k.lower().rstrip("."): v for k, v in (records or {}).items()}
        self.port = port
        self.verbose = verbose
        self.sock = None
        self.thread = None
        self.running = False

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()
        return False

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._respond(data)
            except Exception:
                continue
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def _respond(self, query):
        if len(query) < 12:
            return None
        txn = query[0:2]
        qname, offset = _decode_name(query, 12)
        if offset + 4 > len(query):
            return None
        qtype, _qclass = struct.unpack("!HH", query[offset:offset + 4])
        question = query[12:offset + 4]

        key = qname.lower().rstrip(".")
        value = self.records.get(key)

        if self.verbose:
            print(f"    dns: {qname} type={qtype} -> {'hit' if value is not None else 'NXDOMAIN'}")

        # Anything that is not a TXT query for a name we hold is an authoritative
        # "no such name". Returning NOERROR-with-no-answer instead would tell the
        # resolver the name exists without a record, which is a different fact and
        # one that RFC 6376 6.1.2 treats differently.
        if value is None or qtype != TYPE_TXT:
            flags = 0x8400 | RCODE_NXDOMAIN
            return txn + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question

        rdata = _txt_rdata(value)
        answer = (
            _encode_name(qname)
            + struct.pack("!HHIH", TYPE_TXT, 1, 300, len(rdata))
            + rdata
        )
        flags = 0x8400 | RCODE_NOERROR
        return txn + struct.pack("!HHHHH", flags, 1, 1, 0, 0) + question + answer
