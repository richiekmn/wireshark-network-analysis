Watch me explain this lab: LoomLinkTBA

# wireshark-network-analysis

Hands-on packet analysis with Wireshark: live capture, display filters, DNS tracing, TCP handshake analysis, extracting cleartext HTTP credentials, reconstructing TCP streams, and saving captures as evidence.

# Lab 2: Wireshark & Network Analysis

**Packet capture · Traffic analysis · Network security fundamentals**

I used Wireshark to capture and read live network traffic by filtering thousands of packets down to the necessary few, tracing a DNS lookup, reading a TCP handshake, pulling cleartext credentials off an unencrypted login, reconstructing a full conversation, and saving the capture as evidence. Below is what I did, the filters I used, and what I took away.

**Note:** I only captured traffic on my own virtual machine and network, and only submitted credentials to a dedicated test login website. Capturing other people's traffic without permission is unethical.

| | |
|---|---|
| **Tool** | Wireshark (free, open source) |
| **Environment** | Azure VM |
| **Time** | 2 hours |

---

## What network analysis is for

Networks carry everything an organisation produces: emails, database queries, login credentials, file transfers, API calls. When a service is unreachable, a user reports slow performance, or a security alert fires, the network is almost always involved, and the only way to know what is actually happening is to look at the packets.

---

## Key concepts I needed before the exercises made sense:

- **Packet:** a small unit of data with a header (source IP, destination IP, ports) and a payload. Pages and emails travel as many packets that get reassembled at the destination.
- **Protocol:** the rules for how data is formatted and sent. DNS resolves names, HTTP carries web content, TCP guarantees delivery, ICMP powers ping.
- **TCP three way handshake:** `SYN` → `SYN, ACK` → `ACK`. A `SYN` with no `SYN, ACK` means the connection was refused or the server is unreachable.
- **DNS:** translates names like `google.com` into IP addresses. If DNS breaks, nothing works.
- **HTTP vs HTTPS:** HTTP is unencrypted, so anyone on the path can read it, credentials included. HTTPS adds TLS so captured packets are unreadable.

---

## What I did

### 1. First live capture
Installed and opened Wireshark, double clicked the interface with the **moving line graph** (that's the one carrying traffic: WiFi or Ethernet), browsed a few sites for about 30 seconds, then clicked the red **Stop** button. Even 30 seconds of browsing produces hundreds or thousands of packets, which is exactly why display filters exist.

### 2. Display filters
Display filters hide everything except what you ask for, without discarding anything from the capture. **Capture filters** work the other way: they limit what gets recorded in the first place. I used display filters throughout so I could look at the same capture through different lenses.

| Filter | What it shows | When to use it |
|---|---|---|
| `dns` | DNS queries and responses | Name resolution problems, unusual domain lookups |
| `http` | Unencrypted HTTP traffic | Finding cleartext data |
| `tcp` | All TCP traffic | Starting point for connectivity issues |
| `tcp.flags.syn == 1` | Connection attempts | Seeing who is trying to connect to what ||
| `ip.addr == <host IP>` | All traffic to or from one host | Isolating a host in a busy capture |
| `http.request` | HTTP GET and POST requests | Spotting web requests and possible exfiltration |

### 3. DNS lookup (the invisible step before every connection)
Started a capture, then ran a lookup from a **separate terminal** (Wireshark has no terminal of its own):
```
nslookup google.com
```
<img width="1429" height="876" alt="DNSLookup" src="https://github.com/user-attachments/assets/3936b369-fe47-4d53-b6b2-4ae40fbd7533" />

Stopped the capture and applied the filter `dns`. I found the **Standard query A google.com** (my machine asking) and the **Standard query response A google.com**, expanded **Domain Name System (response) → Answers**, and confirmed the IP matched what `nslookup` printed. The query and response share the same transaction ID. An **A record** maps a name to an IPv4 address (type `1` in the packet).

**Note:** unexpected queries to unusual domains are often the first sign of malware calling home to a command and control server.

### 4. TCP three way handshake
Started a fresh capture, then made a real HTTP connection:
```bash
http://zero.webappsecurity.com
```
Found the host's IP (`nslookup zero.webappsecurity.com`), then filtered:
```
tcp and ip.addr == 54.82.22.214
```
<img width="1459" height="827" alt="TCPThreeWayHandshake" src="https://github.com/user-attachments/assets/18002f64-e533-46ed-8741-49468a645dd7" />


| Packet | Flags | Meaning |
|---|---|---|
| 1st | `SYN` | My machine: I want to connect |
| 2nd | `SYN, ACK` | The server: request received, connection accepted |
| 3rd | `ACK` | My machine: connection open, ready to send data |

All three present means the connection **succeeded**. A `SYN` with no reply means refused or unreachable, and a `RST` means the connection was forcibly closed. Those two patterns are the first things to look for when diagnosing connectivity.

### 5. Cleartext credentials over HTTP (the main event)
On a plain **HTTP** test login page (zero.webappsecurity.com), I submitted a test username (testDummy) and password (simplePassword) while capturing, stopped the capture, and filtered:
```
http.request.method == "POST"
```
<img width="1070" height="800" alt="CleartextCredentials" src="https://github.com/user-attachments/assets/6170a96e-f557-46cd-b9fc-2589ff7a82b8" />


Clicking the **POST** packet and expanding the **HTML Form URL Encoded** layer showed the username and password in plaintext. Anyone on the network path (a coffee shop router, an ISP, a man in the middle) could read them exactly as typed. Over HTTPS the same request shows up as encrypted `TLS / Application Data`. This is how security teams prove the problem to developers who resist adding TLS.

### 6. Follow TCP Stream
<img width="712" height="797" alt="TCPStream" src="https://github.com/user-attachments/assets/4aeacff8-80b6-4827-9d83-43226f8b573e" />


Right-clicked an HTTP packet and chose **Follow → TCP Stream**. Wireshark reassembled the connection into one readable conversation: **red** text is my browser's request, **blue** text is the server's response. Packets are fragments, and the stream shows what was actually requested, what came back, and what data moved. This is the core technique for reconstructing a network event.

### 7. Saved and exported captures
```
File → Save As → .pcapng                                  # full capture with timestamps and metadata
Apply a display filter → File → Export Specified Packets → Displayed   # only the matching packets
File → Open → select your .pcapng                          # reopen later
```
---

## Pitfalls and fixes

| Moment | What to know |
|---|---|
| Capture comes up empty | Capture on the interface with the moving line graph. A dead interface records nothing. |
| No capture permission | Windows needs Npcap, macOS needs ChmodBPF, Linux needs membership in the `wireshark` group (then log out and back in). |
| No handshake after `nslookup` | `nslookup` only does DNS and never opens a TCP connection. Reach the host with a browser or `curl` to get `SYN` / `SYN, ACK` / `ACK`. |
| Browser shows no HTTP traffic | Modern browsers often upgrade to HTTPS. Use `curl http://...` or a site that stays on HTTP. |
| Filter bar turns red | Invalid filter syntax. String values need quotes: `http.request.method == "POST"`. |
| Filtering by host | The field is `ip.addr`, not `tcp.addr`. |
| Used `nslookup` inside Wireshark | Wireshark has no terminal. Run commands in a separate terminal window while the capture runs. |

---

## Key takeaways

1. **Filters are the whole skill.** Raw capture is noise. `dns`, `http`, `ip.addr ==`, and `tcp.flags.syn == 1` turn thousands of packets into easily interpreted chunks.
2. **DNS is not a connection.** Resolving a name and connecting to a host are separate events on the wire.
3. **HTTP is readable, HTTPS is not.** A plaintext password in a capture is the clearest argument for TLS everywhere.
4. **Follow TCP Stream is how you investigate.** It turns scattered packets into a conversation you can read end to end.
5. **Save your captures, carefully.** A `.pcapng` is shareable, reopenable evidence, and exporting only displayed packets keeps it focused and limits what you expose.

---

## Filters used (quick reference)

```
dns                                  # DNS queries and responses
tcp                                  # all TCP traffic
tcp and ip.addr == <host IP>         # one host's TCP conversation
tcp.flags.syn == 1                   # connection attempts / handshake start
http                                 # all HTTP traffic
http.request                         # HTTP GET and POST requests
http.request.method == "POST"        # form submissions
```

---

## Verification

| Skill | How I verified it |
|---|---|
| DNS capture | `dns` filter shows a query packet and its response with matching transaction IDs |
| TCP handshake | Found three sequential packets with `SYN`, `SYN, ACK`, and `ACK`, and can explain each |
| Stream reconstruction | Followed a TCP stream and read the full HTTP request and response |
| File management | Saved a capture, closed Wireshark, reopened the file, and confirmed all packets loaded |

---

## Next steps

- Capture an HTTPS connection and compare it with the HTTP login. Use `tls.handshake.type == 1` to find the Client Hello and see the server name that still travels in the clear
- Spot a refused connection by filtering `tcp.flags.reset == 1` against a closed port

---

**Status: complete.** Live capture → display filters → DNS → TCP handshake → cleartext credentials → Follow TCP Stream → save/export.
