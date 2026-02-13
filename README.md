# Sticky Afrojack SVG Decoder

**Uncover The Hidden Poison**

A SVG decoder that detects and decrypts multiple encryption variants used in SVG-based phishing/credential theft campaigns.

---

## Supported Encryption Types

| Type | Method |
|------|--------|
| **Type 1** | Simple XOR | 
| **Type 2** | LCG + Feistel Cipher |
| **Type 3** | DNA Encoding + Fibonacci XOR |
| **Type 4** | Base64 + Dual-Key XOR | 

---

## Features

- Auto-detection of encryption type and parameters
- Attribute parsing 
- Victim email extraction from multiple formats
- IOC extraction (C2 domains, URLs)
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
