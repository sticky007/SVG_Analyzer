# Sticky Afrojack SVG Decoder

**Uncover The Hidden Poison**

A SVG decoder that detects and decrypts multiple encryption variants used in SVG-based phishing/credential theft campaigns.

---

## Supported Encryption Types

| Type | Method | Detection Pattern |
|------|--------|-------------------|
| **Type 1** | Simple XOR | `String.fromCharCode` key |
| **Type 2** | LCG + Feistel Cipher | `data-t` + `data-*` attributes |
| **Type 3** | DNA Encoding + Fibonacci XOR | `xlink:href` Base64 with ACGT |
| **Type 4** | Base64 + Dual-Key XOR | Split hex keys + obfuscated eval |

---

## Features

- Auto-detection of encryption type and parameters
- Universal attribute parsing (handles `data-nx`, `data-xx`, `data-*`, etc.)
- Victim email extraction from multiple formats
- IOC extraction (C2 domains, URLs)
- Behavior analysis (redirects, script injection, C2 communication)
- Quick summary with key findings

---

## Usage

```bash
python3 sticky_SVG_decoder.py malware.svg          # Full analysis
python3 sticky_SVG_decoder.py malware.svg --raw    # Decoded payload only
python3 sticky_SVG_decoder.py malware.svg -o report.txt  # Save report
```

---

## Author

**Sticky Afrojack** 
