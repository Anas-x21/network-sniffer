#!/usr/bin/env python3
"""
Basic Network Sniffer
=====================

Captures live network traffic and breaks each packet down into its layers:
Ethernet -> IP -> TCP/UDP/ICMP -> payload.

Two backends:
  * scapy      - cross-platform, easier, richer parsing   (default if installed)
  * rawsocket  - Linux only, no dependencies, parses the
                 byte layout manually so you can see how
                 headers are actually laid out on the wire

Usage:
    sudo python3 sniffer.py                        # sniff everything
    sudo python3 sniffer.py -i eth0 -c 50          # 50 packets on eth0
    sudo python3 sniffer.py -f "tcp port 80"       # BPF filter (scapy only)
    sudo python3 sniffer.py --payload              # show payload hexdump
    sudo python3 sniffer.py -b rawsocket           # force the manual parser
    sudo python3 sniffer.py -w capture.log         # also write to a file

Root/administrator privileges are required: capturing frames means putting
the NIC into promiscuous mode, which is a privileged operation.
"""

import argparse
import binascii
import datetime
import socket
import struct
import sys
import textwrap

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

IP_PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP",
}

ETHER_TYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN",
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-server", 68: "DHCP-client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-sub",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

TCP_FLAG_BITS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 13: "Timestamp",
}


class C:
    """Minimal ANSI colours. Disabled automatically when not a TTY."""
    enabled = sys.stdout.isatty()
    DIM = "\033[2m"; BOLD = "\033[1m"; RESET = "\033[0m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"

    @classmethod
    def p(cls, text, colour):
        return f"{colour}{text}{cls.RESET}" if cls.enabled else str(text)


PROTO_COLOUR = {"TCP": C.GREEN, "UDP": C.CYAN, "ICMP": C.YELLOW,
                "ARP": C.MAGENTA, "IPv6": C.BLUE}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

class Reporter:
    """Prints packet summaries to the terminal and, optionally, a log file."""

    def __init__(self, logfile=None, show_payload=False, payload_bytes=96):
        self.fh = open(logfile, "a", encoding="utf-8") if logfile else None
        self.show_payload = show_payload
        self.payload_bytes = payload_bytes
        self.count = 0
        self.stats = {}

    def emit(self, line, plain=None):
        print(line)
        if self.fh:
            self.fh.write((plain if plain is not None else strip_ansi(line)) + "\n")
            self.fh.flush()

    def report(self, pkt):
        """pkt is the normalised dict produced by either backend."""
        self.count += 1
        proto = pkt["proto"]
        self.stats[proto] = self.stats.get(proto, 0) + 1

        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        tag = C.p(f"{proto:<5}", PROTO_COLOUR.get(proto, C.RESET))

        src = pkt.get("src", "?")
        dst = pkt.get("dst", "?")
        if pkt.get("sport") is not None:
            src = f"{src}:{pkt['sport']}"
            dst = f"{dst}:{pkt['dport']}"

        header = (f"[{self.count:>5}] {C.p(ts, C.DIM)}  {tag} "
                  f"{C.p(f'{src:>25}', C.BOLD)} -> {C.p(f'{dst:<25}', C.BOLD)} "
                  f"{pkt['length']:>5} B")
        self.emit(header)

        for detail in pkt.get("details", []):
            self.emit(f"          {C.p('|', C.DIM)} {detail}")

        payload = pkt.get("payload") or b""
        if self.show_payload and payload:
            self.emit(f"          {C.p('|', C.DIM)} payload {len(payload)} bytes:")
            for row in hexdump(payload[:self.payload_bytes]):
                self.emit(f"          {C.p('|   ' + row, C.DIM)}")

    def summary(self):
        self.emit("")
        self.emit(C.p("=" * 60, C.DIM))
        self.emit(C.p(f"Captured {self.count} packets", C.BOLD))
        for proto, n in sorted(self.stats.items(), key=lambda kv: -kv[1]):
            share = (n / self.count * 100) if self.count else 0
            bar = "#" * int(share / 2)
            self.emit(f"  {proto:<6} {n:>6}  {share:5.1f}%  {C.p(bar, C.DIM)}")
        if self.fh:
            self.fh.close()


def strip_ansi(text):
    out, i = [], 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
        else:
            out.append(text[i]); i += 1
    return "".join(out)


def hexdump(data, width=16):
    """Classic offset / hex / ASCII view."""
    rows = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = binascii.hexlify(chunk).decode()
        hexpart = " ".join(hexpart[i:i + 2] for i in range(0, len(hexpart), 2))
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:04x}  {hexpart:<{width * 3}} |{ascii_part}|")
    return rows


def port_name(port):
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def decode_tcp_flags(flags):
    return ",".join(name for bit, name in TCP_FLAG_BITS if flags & bit) or "none"


def guess_app_protocol(sport, dport):
    for p in (sport, dport):
        if p in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[p]
    return None


# ---------------------------------------------------------------------------
# Backend 1: raw sockets (Linux). Headers parsed byte by byte.
# ---------------------------------------------------------------------------

def mac_str(raw):
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(frame):
    """Ethernet II header: 6 bytes dst MAC, 6 bytes src MAC, 2 bytes type."""
    dst, src, ethertype = struct.unpack("!6s6sH", frame[:14])
    return mac_str(dst), mac_str(src), ethertype, frame[14:]


def parse_ipv4(packet):
    """
    IPv4 header. The first byte packs two 4-bit fields:
    high nibble = version, low nibble = header length in 32-bit words.
    """
    ver_ihl = packet[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4          # words -> bytes
    tos, total_len, ident, flags_frag, ttl, proto, checksum = struct.unpack(
        "!BHHHBBH", packet[1:12])
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])
    return {
        "version": version, "ihl": ihl, "tos": tos, "total_len": total_len,
        "id": ident, "df": bool(flags_frag & 0x4000),
        "mf": bool(flags_frag & 0x2000), "frag_offset": (flags_frag & 0x1FFF) * 8,
        "ttl": ttl, "proto": proto, "checksum": checksum,
        "src": src, "dst": dst, "data": packet[ihl:],
    }


def parse_tcp(segment):
    sport, dport, seq, ack, offset_reserved, flags, window, checksum, urg = \
        struct.unpack("!HHLLBBHHH", segment[:20])
    data_offset = (offset_reserved >> 4) * 4
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "flags": flags, "window": window, "checksum": checksum,
        "data": segment[data_offset:],
    }


def parse_udp(datagram):
    sport, dport, length, checksum = struct.unpack("!HHHH", datagram[:8])
    return {"sport": sport, "dport": dport, "length": length,
            "checksum": checksum, "data": datagram[8:]}


def parse_icmp(message):
    icmp_type, code, checksum = struct.unpack("!BBH", message[:4])
    return {"type": icmp_type, "code": code, "checksum": checksum,
            "data": message[4:]}


def normalise_raw(frame):
    """Turn a raw Ethernet frame into the reporter's dict format."""
    if len(frame) < 14:
        return None
    dst_mac, src_mac, ethertype, payload = parse_ethernet(frame)

    if ethertype != 0x0800:                      # not IPv4
        return {
            "proto": ETHER_TYPES.get(ethertype, f"0x{ethertype:04x}"),
            "src": src_mac, "dst": dst_mac, "length": len(frame),
            "details": [f"non-IPv4 ethertype 0x{ethertype:04x}"],
            "payload": payload,
        }

    ip = parse_ipv4(payload)
    proto_name = IP_PROTOCOLS.get(ip["proto"], str(ip["proto"]))
    pkt = {
        "proto": proto_name, "src": ip["src"], "dst": ip["dst"],
        "length": len(frame), "sport": None, "dport": None,
        "details": [
            f"eth  {src_mac} -> {dst_mac}",
            f"ip   ttl={ip['ttl']} id={ip['id']} len={ip['total_len']} "
            f"DF={int(ip['df'])} MF={int(ip['mf'])} hdr={ip['ihl']}B",
        ],
        "payload": ip["data"],
    }

    if proto_name == "TCP" and len(ip["data"]) >= 20:
        tcp = parse_tcp(ip["data"])
        pkt.update(sport=tcp["sport"], dport=tcp["dport"], payload=tcp["data"])
        pkt["details"].append(
            f"tcp  flags=[{decode_tcp_flags(tcp['flags'])}] seq={tcp['seq']} "
            f"ack={tcp['ack']} win={tcp['window']}")
        app = guess_app_protocol(tcp["sport"], tcp["dport"])
        if app:
            pkt["details"].append(f"app  likely {app}")

    elif proto_name == "UDP" and len(ip["data"]) >= 8:
        udp = parse_udp(ip["data"])
        pkt.update(sport=udp["sport"], dport=udp["dport"], payload=udp["data"])
        pkt["details"].append(f"udp  len={udp['length']}")
        app = guess_app_protocol(udp["sport"], udp["dport"])
        if app:
            pkt["details"].append(f"app  likely {app}")

    elif proto_name == "ICMP" and len(ip["data"]) >= 4:
        icmp = parse_icmp(ip["data"])
        label = ICMP_TYPES.get(icmp["type"], "unknown")
        pkt["payload"] = icmp["data"]
        pkt["details"].append(
            f"icmp type={icmp['type']} ({label}) code={icmp['code']}")

    return pkt


def sniff_rawsocket(interface, count, reporter):
    if not hasattr(socket, "AF_PACKET"):
        sys.exit("Raw-socket backend needs Linux (AF_PACKET). "
                 "Install scapy and use -b scapy instead.")
    # ntohs(3) == ETH_P_ALL: hand us every ethertype, not just IP
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    if interface:
        sock.bind((interface, 0))
    seen = 0
    while count == 0 or seen < count:
        frame = sock.recv(65535)
        pkt = normalise_raw(frame)
        if pkt:
            reporter.report(pkt)
            seen += 1


# ---------------------------------------------------------------------------
# Backend 2: scapy
# ---------------------------------------------------------------------------

def normalise_scapy(packet):
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether

    pkt = {"length": len(packet), "details": [], "payload": b"",
           "sport": None, "dport": None, "proto": packet.lastlayer().name}

    if packet.haslayer(Ether):
        e = packet[Ether]
        pkt["details"].append(f"eth  {e.src} -> {e.dst} "
                              f"type={ETHER_TYPES.get(e.type, hex(e.type))}")

    if packet.haslayer(ARP):
        a = packet[ARP]
        op = "request" if a.op == 1 else "reply"
        pkt.update(proto="ARP", src=a.psrc, dst=a.pdst)
        pkt["details"].append(f"arp  {op}: who has {a.pdst}? tell {a.psrc}")
        return pkt

    if packet.haslayer(IP):
        ip = packet[IP]
        pkt.update(src=ip.src, dst=ip.dst,
                   proto=IP_PROTOCOLS.get(ip.proto, str(ip.proto)))
        pkt["details"].append(
            f"ip   ttl={ip.ttl} id={ip.id} len={ip.len} flags={ip.flags}")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        pkt.update(src=ip6.src, dst=ip6.dst, proto="IPv6")
        pkt["details"].append(f"ip6  hlim={ip6.hlim} nh={ip6.nh}")
    else:
        pkt.setdefault("src", "?"); pkt.setdefault("dst", "?")
        return pkt

    if packet.haslayer(TCP):
        t = packet[TCP]
        pkt.update(sport=t.sport, dport=t.dport, proto="TCP")
        pkt["details"].append(
            f"tcp  flags=[{t.flags}] seq={t.seq} ack={t.ack} win={t.window}")
        app = guess_app_protocol(t.sport, t.dport)
        if app:
            pkt["details"].append(f"app  likely {app}")
        pkt["payload"] = bytes(t.payload)

    elif packet.haslayer(UDP):
        u = packet[UDP]
        pkt.update(sport=u.sport, dport=u.dport, proto="UDP")
        pkt["details"].append(f"udp  len={u.len}")
        app = guess_app_protocol(u.sport, u.dport)
        if app:
            pkt["details"].append(f"app  likely {app}")
        pkt["payload"] = bytes(u.payload)
        # DNS is the easiest protocol to read live, so decode the question
        try:
            from scapy.layers.dns import DNS
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                qname = packet[DNS].qd.qname.decode(errors="replace")
                pkt["details"].append(f"dns  query {qname}")
        except Exception:
            pass

    elif packet.haslayer(ICMP):
        i = packet[ICMP]
        label = ICMP_TYPES.get(i.type, "unknown")
        pkt.update(proto="ICMP")
        pkt["details"].append(f"icmp type={i.type} ({label}) code={i.code}")
        pkt["payload"] = bytes(i.payload)

    return pkt


def sniff_scapy(interface, count, bpf_filter, reporter):
    from scapy.all import sniff
    sniff(iface=interface or None,
          filter=bpf_filter or None,
          count=count,               # 0 means "run forever"
          store=False,               # don't hold packets in RAM
          prn=lambda p: reporter.report(normalise_scapy(p)))


# ---------------------------------------------------------------------------
# Optional GUI (Tkinter popup window instead of the terminal)
# ---------------------------------------------------------------------------

class GuiReporter(Reporter):
    """Same as Reporter, but pushes each printed line into a thread-safe
    queue for the Tk window to display, instead of writing to stdout."""

    def __init__(self, line_queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = line_queue

    def emit(self, line, plain=None):
        text = plain if plain is not None else strip_ansi(line)
        self.queue.put(text)
        if self.fh:
            self.fh.write(text + "\n")
            self.fh.flush()


def run_gui(backend, interface, count, bpf_filter, write, show_payload, payload_bytes):
    import os
    import queue
    import threading
    import tkinter as tk
    from tkinter import scrolledtext, font as tkfont

    C.enabled = False  # no ANSI escape codes in a Tk Text widget

    line_queue = queue.Queue()
    reporter = GuiReporter(line_queue, write, show_payload, payload_bytes)
    stop_event = threading.Event()

    root = tk.Tk()
    root.title("Network Sniffer")
    root.geometry("1000x620")
    root.configure(bg="#1e1e1e")

    header = tk.Frame(root, bg="#1e1e1e")
    header.pack(fill="x", padx=10, pady=(10, 0))
    status_var = tk.StringVar(
        value=f"backend={backend}  iface={interface or 'default'}"
              f"{'  filter=' + bpf_filter if bpf_filter else ''}")
    tk.Label(header, textvariable=status_var, fg="#dddddd", bg="#1e1e1e",
             font=("Segoe UI", 10, "bold")).pack(side="left")
    count_var = tk.StringVar(value="0 packets")
    tk.Label(header, textvariable=count_var, fg="#9cdcfe", bg="#1e1e1e",
             font=("Segoe UI", 10, "bold")).pack(side="right")

    mono = tkfont.Font(family="Consolas", size=10)
    text = scrolledtext.ScrolledText(root, bg="#1e1e1e", fg="#d4d4d4",
                                      insertbackground="white", font=mono,
                                      wrap="none", state="disabled")
    text.pack(fill="both", expand=True, padx=10, pady=10)
    text.tag_config("TCP", foreground="#4ec9b0")
    text.tag_config("UDP", foreground="#569cd6")
    text.tag_config("ICMP", foreground="#dcdcaa")
    text.tag_config("ARP", foreground="#c586c0")
    text.tag_config("DIM", foreground="#6a6a6a")

    def on_close():
        stop_event.set()
        root.destroy()
        os._exit(0)  # the capture thread may be blocked inside a C call

    root.protocol("WM_DELETE_WINDOW", on_close)

    def append_line(line):
        tag = None
        if line.startswith("["):
            for proto in ("TCP", "UDP", "ICMP", "ARP"):
                if proto in line:
                    tag = proto
                    break
        elif line.startswith("      "):
            tag = "DIM"
        text.configure(state="normal")
        text.insert("end", line + "\n", tag or ())
        text.see("end")
        text.configure(state="disabled")

    def poll_queue():
        try:
            while True:
                append_line(line_queue.get_nowait())
        except queue.Empty:
            pass
        count_var.set(f"{reporter.count} packets")
        root.after(100, poll_queue)

    def capture_worker():
        try:
            if backend == "scapy":
                from scapy.all import sniff
                sniff(iface=interface or None, filter=bpf_filter or None,
                      count=count, store=False,
                      stop_filter=lambda p: stop_event.is_set(),
                      prn=lambda p: reporter.report(normalise_scapy(p)))
            else:
                sniff_rawsocket(interface, count, reporter)
        except PermissionError:
            line_queue.put("Permission denied - run as administrator / with sudo.")
        except Exception as exc:
            line_queue.put(f"Capture error: {exc}")

    threading.Thread(target=capture_worker, daemon=True).start()
    poll_queue()
    root.mainloop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Basic network sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              sudo python3 sniffer.py -c 20
              sudo python3 sniffer.py -i wlan0 -f "udp port 53" --payload
              sudo python3 sniffer.py -b rawsocket -w capture.log
        """))
    parser.add_argument("-i", "--interface", help="interface, e.g. eth0/wlan0")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="stop after N packets (0 = until Ctrl-C)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter, scapy backend only")
    parser.add_argument("-b", "--backend", choices=["auto", "scapy", "rawsocket"],
                        default="auto")
    parser.add_argument("-w", "--write", help="append plain-text log to file")
    parser.add_argument("--payload", action="store_true",
                        help="hexdump the application payload")
    parser.add_argument("--payload-bytes", type=int, default=96,
                        help="max payload bytes to dump (default 96)")
    parser.add_argument("--gui", action="store_true",
                        help="show output in a popup window instead of the terminal")
    args = parser.parse_args()

    backend = args.backend
    if backend == "auto":
        try:
            import scapy  # noqa: F401
            backend = "scapy"
        except ImportError:
            backend = "rawsocket"

    if args.gui:
        run_gui(backend, args.interface, args.count, args.filter,
                args.write, args.payload, args.payload_bytes)
        return

    reporter = Reporter(args.write, args.payload, args.payload_bytes)
    print(C.p(f"Sniffing with the {backend} backend"
              f"{' on ' + args.interface if args.interface else ''}"
              f"{' filter=' + args.filter if args.filter else ''}. "
              f"Ctrl-C to stop.\n", C.BOLD))

    try:
        if backend == "scapy":
            sniff_scapy(args.interface, args.count, args.filter, reporter)
        else:
            sniff_rawsocket(args.interface, args.count, reporter)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("\nPermission denied - run with sudo / as administrator.")
    finally:
        reporter.summary()


if __name__ == "__main__":
    main()
