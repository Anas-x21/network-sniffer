# Basic Network Sniffer

A Python packet sniffer that captures live network traffic and breaks each packet
down layer by layer: Ethernet → IP → TCP/UDP/ICMP → payload.

## Features

- Two capture backends:
  - **scapy** — cross-platform, supports BPF filters, decodes DNS queries
  - **rawsocket** — Linux only, pure standard library, parses every header
    byte by byte with `struct` so nothing is hidden
- Displays source/destination MAC and IP addresses, ports, and protocol
- Decodes IP fields (TTL, identification, DF/MF fragmentation flags, header length)
- Decodes TCP flags (SYN, ACK, PSH, FIN, RST) and sequence/acknowledgement numbers
- Maps well-known ports to their likely application protocol
- Optional hexdump of the application payload
- Live protocol statistics printed on exit

## Requirements

- Python 3.8+
- `scapy` (optional, but recommended)
- On Windows: [Npcap](https://npcap.com) with "WinPcap API-compatible mode" enabled
- Administrator / root privileges

## Installation

```bash
git clone https://github.com/<your-username>/network-sniffer.git
cd network-sniffer
pip install -r requirements.txt
```

## Usage

```bash
# Windows (run terminal as Administrator)
python sniffer.py -c 20 --payload

# Linux / macOS
sudo python3 sniffer.py -c 20 --payload
```

### Options

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Interface to capture on (e.g. `eth0`, `wlan0`) |
| `-c`, `--count` | Stop after N packets (0 = run until Ctrl-C) |
| `-f`, `--filter` | BPF filter string, scapy backend only |
| `-b`, `--backend` | `auto`, `scapy`, or `rawsocket` |
| `-w`, `--write` | Append a plain-text log to a file |
| `--payload` | Hexdump the application payload |
| `--payload-bytes` | Maximum payload bytes to dump (default 96) |

### Examples

```bash
sudo python3 sniffer.py -i wlan0 -f "udp port 53" --payload   # DNS only
sudo python3 sniffer.py -f "icmp"                             # ping traffic
sudo python3 sniffer.py -b rawsocket -w capture.log           # manual parser
```

## Sample output

```
[    1] 23:49:33.714  TCP     4.150.223.114:443 -> 192.168.1.5:49217     153 B
          | eth  90:03:2e:94:64:d0 -> 60:45:2e:6b:5a:67 type=IPv4
          | ip   ttl=107 id=30723 len=139 flags=DF
          | tcp  flags=[PA] seq=246394588 ack=782069159 win=16386
          | app  likely HTTPS
          | payload 99 bytes:
          |   0000  17 03 03 00 5e df 5b db 3d 92 7c 8b a6 6f 32 96  |....^.[.=.|..o2.|
```

## What the output teaches

- **Ethernet** is 14 bytes: destination MAC, source MAC, and a 2-byte ethertype
  (`0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6).
- **IPv4** packs version and header length into a single byte, which is why the
  header size must be computed as `(byte & 0x0F) * 4` rather than assumed to be 20.
- **TCP flags** are a bitmask. A new connection appears as SYN → SYN,ACK → ACK
  across three consecutive lines.
- **Encryption is visible in the payload.** DNS on port 53 shows the queried
  domain in cleartext; HTTPS on port 443 shows a TLS record header followed by
  ciphertext.

## Legal notice

Capture traffic only on networks you own or have written permission to test.
Passively intercepting other people's traffic on shared, campus, or public
networks is illegal in most jurisdictions regardless of intent.

## Licence

MIT
