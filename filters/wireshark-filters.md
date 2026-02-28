# 🔎 Wireshark Display Filters Reference

This file documents all display filters used during the **Cloud Network Traffic Analysis Project**.

---

## 🌐 DNS Traffic

| Purpose | Filter |
|---------|--------|
| All DNS traffic | `dns` |
| DNS Queries only | `dns.flags.response == 0` |
| DNS Responses only | `dns.flags.response == 1` |

---

## 🤝 TCP Handshake Analysis

| Purpose | Filter |
|---------|--------|
| Initial SYN packets | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN-ACK packets | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| All SYN packets | `tcp.flags.syn == 1` |

---

## 🌍 HTTP Traffic

| Purpose | Filter |
|---------|--------|
| All HTTP traffic | `http` |
| HTTP GET requests | `http.request.method == "GET"` |
| HTTP POST requests | `http.request.method == "POST"` |

---

## 🔐 TLS / HTTPS Traffic

| Purpose | Filter |
|---------|--------|
| All TLS traffic | `tls` |
| TLS Handshake only | `tls.handshake` |
| Client Hello | `tls.handshake.type == 1` |
| Server Hello | `tls.handshake.type == 2` |
| TLS SNI inspection | `tls.handshake.extensions_server_name` |

---

## 🚨 Suspicious Pattern Detection

| Purpose | Filter |
|---------|--------|
| TCP retransmissions | `tcp.analysis.retransmission` |
| Fast retransmissions | `tcp.analysis.fast_retransmission` |
| Non-standard port traffic | `tcp.dstport != 80 && tcp.dstport != 443 && tcp.dstport != 53` |

---

## 🔍 Combined Protocol View
dns || tcp || http || tls

---

**Note:** These filters were used for traffic inspection, anomaly identification, and cloud security mapping within the project.
