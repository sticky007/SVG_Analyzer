#!/usr/bin/env python3
"""
Sticky Afrojack - SVG Malware Decoder
Uncover The Hidden Poison

Universal decoder for SVG-based malware with encrypted payloads.
Supports multiple encryption types and attribute variations.

Author: Sticky Afrojack
Email: sticky.afrojack@proton.me
Team: Cyber Threat Research and Hunting
"""

import sys
import re
import base64
import argparse
import json
from pathlib import Path
from datetime import datetime

__author__ = "Sticky Afrojack"
__email__ = "sticky.afrojack@proton.me"
__team__ = "Cyber Threat Research and Hunting"
__tagline__ = "Uncover The Hidden Poison"

# ============================================================================
# TERMINAL COLORS
# ============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    ORANGE = '\033[38;5;208m'
    PINK = '\033[38;5;213m'
    LIME = '\033[38;5;118m'
    GOLD = '\033[38;5;220m'
    BRIGHT_RED = '\033[38;5;196m'
    BRIGHT_CYAN = '\033[38;5;51m'

def banner():
    print(f"""
{Colors.BRIGHT_RED}{Colors.BOLD}   _____ _    ______   {Colors.GOLD}____  _____ ____ ___  ____  _____ ____  
{Colors.BRIGHT_RED}  / ___/| |  / / ___/  {Colors.GOLD}|  _ \\| ____/ ___/ _ \\|  _ \\| ____|  _ \\ 
{Colors.BRIGHT_RED}  \\__ \\ | | / / |  _   {Colors.GOLD}| | | |  _|| |  | | | | | | |  _| | |_) |
{Colors.BRIGHT_RED} ___) || |/ /| |_| |  {Colors.GOLD}| |_| | |__| |__| |_| | |_| | |___|  _ < 
{Colors.BRIGHT_RED}|____/ |___/  \\____|  {Colors.GOLD}|____/|_____\\____\\___/|____/|_____|_| \\_\\{Colors.END}

{Colors.BRIGHT_CYAN}  ─────────────────────────────────────────────────────────────────{Colors.END}
{Colors.WHITE}{Colors.BOLD}              ☠  Uncover The Hidden Poison  ☠{Colors.END}
{Colors.BRIGHT_CYAN}  ─────────────────────────────────────────────────────────────────{Colors.END}

{Colors.YELLOW}    Author : {Colors.WHITE}Sticky Afrojack{Colors.END}
{Colors.YELLOW}    Email  : {Colors.WHITE}sticky.afrojack@proton.me{Colors.END}
{Colors.YELLOW}    Team   : {Colors.WHITE}Cyber Threat Research and Hunting {Colors.END}

{Colors.BRIGHT_CYAN}  ─────────────────────────────────────────────────────────────────────────────────{Colors.END}
""")

# ============================================================================
# CRYPTO FUNCTIONS
# ============================================================================

def math_imul(a, b):
    """JavaScript Math.imul equivalent - 32-bit integer multiplication"""
    return ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF

class XORKey:
    """Class to store and display XOR key information"""
    def __init__(self, key_type, key_value, key_source, key_bytes=None):
        self.type = key_type
        self.value = key_value
        self.source = key_source
        self.bytes = key_bytes or []
    
    def __str__(self):
        return f"Type: {self.type}, Value: {self.value}, Source: {self.source}"

# ============================================================================
# TYPE 1: SIMPLE XOR DECODER
# ============================================================================

class SimpleXORDecoder:
    """Decoder for simple XOR encrypted payloads"""
    
    KNOWN_KEYS = [
        "secretkey",
        "password",
        "key12345",
        "malware",
        "decrypt",
        "encode",
        "hidden",
        "payload",
    ]
    
    def __init__(self):
        self.detected_key = None
        self.key_info = None
    
    def detect_key_from_charcode(self, content):
        """Extract XOR key from String.fromCharCode pattern"""
        pattern = r'String\.fromCharCode\(([0-9,\s]+)\)'
        matches = re.findall(pattern, content)
        
        for match in matches:
            try:
                char_codes = [int(x.strip()) for x in match.split(',')]
                key = ''.join(chr(c) for c in char_codes if 32 <= c < 127)
                if len(key) >= 3:
                    self.detected_key = key
                    self.key_info = XORKey(
                        key_type="String.fromCharCode",
                        key_value=key,
                        key_source=f"String.fromCharCode({match})",
                        key_bytes=char_codes
                    )
                    return key
            except:
                continue
        return None
    
    def detect_key_bruteforce(self, hex_payload):
        """Try known keys against the payload"""
        if len(hex_payload) < 20:
            return None
        
        for key in self.KNOWN_KEYS:
            try:
                decoded = self.xor_decode(hex_payload[:100], key)
                if any(x in decoded.lower() for x in ['function', 'var ', 'const ', 'let ', 'fetch', 'document']):
                    self.detected_key = key
                    self.key_info = XORKey(
                        key_type="Known Key (Bruteforce)",
                        key_value=key,
                        key_source="Matched against known key list",
                        key_bytes=[ord(c) for c in key]
                    )
                    return key
            except:
                continue
        return None
    
    def xor_decode(self, hex_string, key):
        """XOR decode hex string with key"""
        result = []
        key_len = len(key)
        
        for i in range(0, len(hex_string), 2):
            byte_val = int(hex_string[i:i+2], 16)
            key_char = ord(key[(i // 2) % key_len])
            result.append(chr(byte_val ^ key_char))
        
        return ''.join(result)
    
    def decode(self, hex_payload, content):
        """Main decode function"""
        key = self.detect_key_from_charcode(content)
        if not key:
            key = self.detect_key_bruteforce(hex_payload)
        
        if key:
            return self.xor_decode(hex_payload, key)
        return None

# ============================================================================
# TYPE 2: LCG + FEISTEL DECODER
# ============================================================================

class LCGFeistelDecoder:
    """Decoder for LCG XOR + Feistel cipher encrypted payloads"""
    
    def __init__(self):
        self.key_info = None
        self.params = None
    
    def parse_params(self, data_params):
        """Parse decryption parameters"""
        parts = data_params.split('.')
        if len(parts) != 6:
            return None
        
        self.params = {
            'op1_type': int(parts[0]),
            'op1_key': int(parts[1]),
            'op2_type': int(parts[2]),
            'op2_key': int(parts[3]),
            'seed': int(parts[4]),
            'output_len': int(parts[5])
        }
        
        self.key_info = XORKey(
            key_type="LCG + Feistel Cipher",
            key_value=data_params,
            key_source="data-* attribute",
            key_bytes=[
                f"Op1: Type={self.params['op1_type']}, Key={self.params['op1_key']}",
                f"Op2: Type={self.params['op2_type']}, Key={self.params['op2_key']}",
                f"Seed: {self.params['seed']}",
                f"LCG Multiplier: 0x41c64e6d (1103515245)",
                f"LCG Increment: 0x3039 (12345)",
                f"Feistel Rounds: 2"
            ]
        )
        
        return self.params
    
    def decrypt_operation(self, op_type, op_key, seed_val, data):
        """Apply decryption operation"""
        result = data.copy()
        
        if op_type == 0:
            # LCG-based XOR
            state = seed_val
            for i in range(len(result)):
                state = (math_imul(state, 0x41c64e6d) + 0x3039) & 0xFFFFFFFF
                key_byte = (state >> 16) & 0xFF
                result[i] ^= key_byte
                
        elif op_type == 1:
            # Subtraction cipher
            for i in range(len(result)):
                result[i] = (result[i] - op_key + 256) % 256
                
        elif op_type == 2:
            # Shuffle/permutation
            length = len(result)
            indices = list(range(length))
            state = seed_val
            for i in range(length - 1, 0, -1):
                state = (math_imul(state, 0x19660d) + 0x3c6ef35f) & 0xFFFFFFFF
                j = ((state >> 16) % (i + 1))
                indices[i], indices[j] = indices[j], indices[i]
            inverse = [0] * length
            for i in range(length):
                inverse[indices[i]] = result[i]
            result = inverse
            
        elif op_type == 3:
            # Feistel cipher
            length = len(result)
            for round_num in range(1, -1, -1):
                round_key = (seed_val + round_num * 0x1eef) & 0xFFFFFF
                for i in range(0, length - 1, 2):
                    left = result[i]
                    right = result[i + 1]
                    f = (right * (round_key & 0xFF) + (round_key >> 8)) ^ (round_key >> 16)
                    f = f & 0xFF
                    left ^= f
                    result[i] = left
                    result[i + 1] = right
                    
        elif op_type == 4:
            # Sequential XOR
            for i in range(len(result)):
                key_byte = (op_key + i * 7) & 0xFF
                result[i] ^= key_byte
        
        return result
    
    def decode(self, data_t, data_params):
        """Main decode function"""
        params = self.parse_params(data_params)
        if not params:
            return None
        
        payload_bytes = [int(data_t[i:i+2], 16) for i in range(0, len(data_t), 2)]
        
        # First pass
        decrypted = self.decrypt_operation(
            params['op2_type'],
            params['op2_key'],
            params['seed'] + 1,
            payload_bytes
        )
        
        # Second pass
        decrypted = self.decrypt_operation(
            params['op1_type'],
            params['op1_key'],
            params['seed'],
            decrypted
        )
        
        output = ''.join(chr(b) for b in decrypted[:params['output_len']] 
                        if 32 <= b < 127 or b in [9, 10, 13])
        
        return output

# ============================================================================
# TYPE 3: DNA ENCODING + FIBONACCI XOR DECODER
# ============================================================================

class DNAFibonacciDecoder:
    """
    Decoder for DNA-encoded + Fibonacci XOR encrypted payloads.
    
    This variant uses:
    1. DNA encoding (ACGT letters represent 2-bit values)
    2. Fibonacci-like sequence XOR for decryption
    
    Structure: "DNASTRING|HEXPARAMS"
    - DNA string: Encoded payload using A=0, C=1, G=2, T=3
    - Hex params: 8 chars seed + 4 chars length
    """
    
    def __init__(self):
        self.key_info = None
        self.params = None
    
    def extract_from_base64(self, content):
        """Extract DNA payload from Base64 encoded xlink:href"""
        # Find Base64 in xlink:href or data: URI
        match = re.search(r'xlink:href="data:[^;]+;base64,([A-Za-z0-9+/=]+)"', content)
        if not match:
            match = re.search(r'href="data:[^;]+;base64,([A-Za-z0-9+/=]+)"', content)
        
        if match:
            try:
                b64_data = match.group(1)
                decoded_js = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
                
                # Extract DNA string and parameters - handle various formats
                # Format: var ho="ACGTACGT...|hexparams"
                # Allow ACGTU (U may appear as variant/corruption)
                dna_match = re.search(r'var\s+\w+\s*=\s*["\']([ACGTU]{50,})\|([0-9a-fA-F]{8,})["\']', decoded_js)
                if dna_match:
                    return {
                        'dna_string': dna_match.group(1),
                        'hex_params': dna_match.group(2),
                        'raw_js': decoded_js
                    }
            except:
                pass
        return None
    
    def parse_params(self, hex_params):
        """Parse the hex parameters"""
        if len(hex_params) < 12:
            return None
        
        seed = int(hex_params[:8], 16)
        length = int(hex_params[8:12], 16)
        
        self.params = {
            'seed': seed,
            'length': length,
            'hex_params': hex_params
        }
        
        self.key_info = XORKey(
            key_type="DNA Encoding + Fibonacci XOR",
            key_value=hex_params,
            key_source="Base64 xlink:href payload",
            key_bytes=[
                f"Seed: 0x{hex_params[:8]} ({seed})",
                f"Length: 0x{hex_params[8:12]} ({length} bytes)",
                f"DNA Alphabet: A=0, C=1, G=2, T=3",
                f"Fibonacci XOR: NB[n] = (NB[n-1] + NB[n-2]) % 256"
            ]
        )
        
        return self.params
    
    def decode_dna(self, dna_string):
        """Decode DNA string to bytes"""
        # U is treated as T (RNA uses U instead of T)
        dna_map = {'A': 0, 'C': 1, 'G': 2, 'T': 3, 'U': 3}
        result = []
        
        for i in range(0, len(dna_string), 4):
            if i + 3 < len(dna_string):
                byte_val = (dna_map.get(dna_string[i], 0) << 6) | \
                          (dna_map.get(dna_string[i+1], 0) << 4) | \
                          (dna_map.get(dna_string[i+2], 0) << 2) | \
                          dna_map.get(dna_string[i+3], 0)
                result.append(byte_val)
        
        return result
    
    def generate_fibonacci_key(self, seed, length):
        """Generate Fibonacci-like XOR key sequence"""
        key = [seed % 256, (seed >> 8) % 256]
        
        for i in range(2, 256):
            key.append((key[i-1] + key[i-2]) % 256)
        
        return key
    
    def decode(self, content):
        """Main decode function"""
        extracted = self.extract_from_base64(content)
        if not extracted:
            return None
        
        params = self.parse_params(extracted['hex_params'])
        if not params:
            return None
        
        # Decode DNA to bytes
        dna_bytes = self.decode_dna(extracted['dna_string'])
        
        # Generate Fibonacci key
        fib_key = self.generate_fibonacci_key(params['seed'], params['length'])
        
        # XOR decrypt
        decrypted = []
        for i in range(min(params['length'], len(dna_bytes))):
            decrypted.append(dna_bytes[i] ^ fib_key[i % 256])
        
        # Convert to string
        result = ''.join(chr(b) for b in decrypted if 32 <= b < 127 or b in [9, 10, 13])
        
        return result


# ============================================================================
# TYPE 4: BASE64 + DUAL-KEY XOR DECODER
# ============================================================================

class DualKeyXORDecoder:
    """
    Decoder for Base64 + Dual-Key XOR encrypted payloads.
    
    This variant uses:
    1. Base64 encoded payload in a variable
    2. Two separate key parts that are concatenated
    3. Simple XOR with the combined key
    4. Execution via obfuscated eval ("evil".replace("i","a"))
    """
    
    def __init__(self):
        self.key_info = None
        self.params = None
    
    def extract_components(self, content):
        """Extract payload and keys from the JavaScript"""
        components = {}
        
        # Find Base64 payload - look for long Base64 strings
        b64_patterns = [
            r'(?:let|var|const)\s+\w+\s*=\s*["\']([A-Za-z0-9+/=]{50,})["\']',
        ]
        
        for pattern in b64_patterns:
            match = re.search(pattern, content)
            if match:
                components['payload_b64'] = match.group(1)
                break
        
        # Find key parts - typically hex strings (6+ chars)
        key_matches = re.findall(r'(?:let|var|const)\s+(\w+)\s*=\s*["\']([0-9a-fA-F]{6,})["\']', content)
        if key_matches:
            components['key_parts'] = key_matches
        
        # Check for key concatenation pattern: key1 + key2
        concat_match = re.search(r'(?:let|var|const)\s+(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)', content)
        if concat_match:
            components['concat_vars'] = (concat_match.group(2), concat_match.group(3))
        
        # Find victim identifier
        victim_patterns = [
            r'(?:let|var|const)?\s*\w+\s*=\s*["\']([^"\']*@[^"\']+)["\']',
            r'(?:let|var|const)?\s*\w+\s*=\s*["\'](\*[^"\']+@[^"\']+)["\']',
        ]
        for pattern in victim_patterns:
            match = re.search(pattern, content)
            if match:
                components['victim'] = match.group(1)
                break
        
        return components
    
    def decode(self, content):
        """Main decode function"""
        components = self.extract_components(content)
        
        if 'payload_b64' not in components or 'key_parts' not in components:
            return None
        
        # Build combined key
        key_dict = {name: value for name, value in components['key_parts']}
        
        # Try to find the concatenation order
        combined_key = None
        if 'concat_vars' in components:
            var1, var2 = components['concat_vars']
            if var1 in key_dict and var2 in key_dict:
                combined_key = key_dict[var1] + key_dict[var2]
        
        if not combined_key:
            # Just concatenate all keys found
            combined_key = ''.join(value for name, value in components['key_parts'])
        
        # Decode and decrypt
        try:
            decoded = base64.b64decode(components['payload_b64'])
            result = []
            for i, byte in enumerate(decoded):
                key_char = ord(combined_key[i % len(combined_key)])
                result.append(chr(byte ^ key_char))
            
            decrypted = ''.join(result)
            
            self.key_info = XORKey(
                key_type="Base64 + Dual-Key XOR",
                key_value=combined_key,
                key_source="Concatenated key variables",
                key_bytes=[
                    f"Key Parts: {len(components['key_parts'])} parts found",
                    f"Combined Key: {combined_key}",
                    f"Key Length: {len(combined_key)} characters",
                    f"Payload Length: {len(decoded)} bytes"
                ]
            )
            
            self.params = {
                'combined_key': combined_key,
                'victim': components.get('victim', None)
            }
            
            return decrypted
        except Exception as e:
            return None


# ============================================================================
# TYPE 5: BASE64 DECODER
# ============================================================================

class Base64Decoder:
    """Decoder for Base64 encoded payloads"""
    
    def __init__(self):
        self.key_info = None
    
    def is_base64(self, s):
        """Check if string is valid Base64"""
        if not s or len(s) < 4:
            return False
        pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        return bool(re.match(pattern, s))
    
    def decode(self, encoded_string):
        """Decode Base64 string - handles multiple prefix formats"""
        try:
            clean = encoded_string
            original = encoded_string
            
            # Handle format: #$XXX$base64string or similar
            # Remove any prefix characters and find the Base64 part
            if '$' in clean:
                parts = clean.split('$')
                for part in reversed(parts):
                    part = part.strip()
                    if self.is_base64(part) and len(part) > 10:
                        clean = part
                        break
            
            # Remove leading special characters
            clean = re.sub(r'^[#$@!%^&*]+', '', clean).strip()
            
            if self.is_base64(clean):
                decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
                self.key_info = XORKey(
                    key_type="Base64 Encoding",
                    key_value="Standard Base64",
                    key_source=f"Decoded from: {original[:40]}...",
                    key_bytes=["Alphabet: A-Za-z0-9+/="]
                )
                return decoded
        except Exception as e:
            pass
        return None

# ============================================================================
# TYPE 4: CHARACTER ARRAY DECODER
# ============================================================================

class CharArrayDecoder:
    """Decoder for character array obfuscation"""
    
    def __init__(self):
        self.key_info = None
    
    def decode(self, content):
        """Extract and join character arrays"""
        pattern = r'\[((?:["\'][^"\']+["\'],?\s*)+)\]\.join\(["\']["\']?\)'
        matches = re.findall(pattern, content)
        
        results = []
        for match in matches:
            chars = re.findall(r'["\']([^"\']+)["\']', match)
            if chars:
                joined = ''.join(chars)
                results.append(joined)
        
        if results:
            self.key_info = XORKey(
                key_type="Character Array Obfuscation",
                key_value="Array.join()",
                key_source="Detected [].join('') pattern",
                key_bytes=["URL split into individual characters to evade detection"]
            )
        
        return results

# ============================================================================
# MAIN SVG ANALYZER
# ============================================================================

class SVGMalwareAnalyzer:
    """Main analyzer class that handles all SVG malware types"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.content = None
        self.malware_type = None
        self.components = {}
        self.decoded_payload = None
        self.key_info = None
        self.iocs = {}
        self.behaviors = []
        
        self.simple_xor = SimpleXORDecoder()
        self.lcg_feistel = LCGFeistelDecoder()
        self.dna_fibonacci = DNAFibonacciDecoder()
        self.dual_key_xor = DualKeyXORDecoder()
        self.base64_decoder = Base64Decoder()
        self.char_array = CharArrayDecoder()
    
    def load_file(self):
        """Load SVG file content"""
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.content = f.read()
            return True
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to load file: {e}{Colors.END}")
            return False
    
    def detect_malware_type(self):
        """Detect the type of SVG malware"""
        types_detected = []
        
        # Check for Type 4: Dual-Key XOR (Base64 payload + concatenated hex keys)
        if re.search(r'(?:let|var|const)\s+\w+\s*=\s*["\'][A-Za-z0-9+/=]{50,}["\']', self.content):
            # Check for hex key parts
            if re.search(r'(?:let|var|const)\s+\w+\s*=\s*["\'][0-9a-fA-F]{6,}["\']', self.content):
                # Check for key concatenation
                if re.search(r'(?:let|var|const)\s+\w+\s*=\s*\w+\s*\+\s*\w+', self.content):
                    types_detected.append("Type 4: Base64 + Dual-Key XOR")
        
        # Check for Type 3: DNA + Fibonacci (xlink:href with Base64)
        if 'xlink:href="data:' in self.content and 'base64,' in self.content:
            match = re.search(r'base64,([A-Za-z0-9+/=]+)', self.content)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')
                    if re.search(r'[ACGTU]{100,}\|[0-9a-fA-F]+', decoded):
                        types_detected.append("Type 3: DNA Encoding + Fibonacci XOR (xlink:href)")
                except:
                    pass
        
        # Check for Type 4: Dual-Key XOR (split hex keys + Base64)
        key_matches = re.findall(r'(?:let|var|const)\s+\w+\s*=\s*["\']([0-9a-fA-F]{6,24})["\']', self.content)
        b64_match = re.search(r'(?:let|var|const)\s+\w+\s*=\s*["\']([A-Za-z0-9+/=]{50,})["\']', self.content)
        if len(key_matches) >= 2 and b64_match:
            types_detected.append("Type 4: Base64 + Dual-Key XOR")
        
        # Check for Type 2: LCG + Feistel (data-t with ANY data-* parameter attribute)
        if 'data-t=' in self.content:
            param_match = re.search(r'data-([a-zA-Z][a-zA-Z0-9]*)\s*=\s*["\'](\d+\.\d+\.\d+\.\d+\.\d+\.\d+)["\']', self.content)
            if param_match:
                param_name = param_match.group(1)
                types_detected.append(f"Type 2: LCG + Feistel Cipher (data-t/data-{param_name})")
        
        # Check for Type 1: Simple XOR
        if re.search(r'String\.fromCharCode\([0-9,\s]+\)', self.content):
            types_detected.append("Type 1: Simple XOR (String.fromCharCode key)")
        
        # Check for Character array obfuscation
        if re.search(r'\[["\'][a-zA-Z]["\'](\s*,\s*["\'][a-zA-Z]["\'])+\]\.join', self.content):
            types_detected.append("Obfuscation: Character Array")
        
        # Check for obfuscated eval
        if 'evil' in self.content and 'replace' in self.content:
            types_detected.append("Execution Method: Obfuscated eval (evil.replace)")
        
        # Check for window.location redirect
        if 'window.location' in self.content or 'location.href' in self.content:
            types_detected.append("Attack Type: Browser Redirect")
        
        # Check for obfuscation patterns
        if re.search(r'_0x[a-f0-9]+', self.content):
            types_detected.append("JavaScript Obfuscation: Hexadecimal naming")
        
        if 'constructor' in self.content.lower():
            types_detected.append("Execution Method: constructor chain")
        
        # Check for atob usage (including URL encoded)
        if 'atob' in self.content or '%61%74%6F%62' in self.content or 'decodeURIComponent' in self.content:
            types_detected.append("Encoding: atob (Base64 decode)")
        
        self.malware_type = types_detected
        return types_detected
    
    def extract_components(self):
        """Extract all components from SVG - UNIVERSAL attribute detection"""
        
        # data-t (encrypted payload) - the payload attribute
        match = re.search(r'data-t\s*=\s*["\']([0-9a-fA-F]+)["\']', self.content)
        if match:
            self.components['data_t'] = match.group(1)
        
        # UNIVERSAL: Find ANY data-* attribute with 6 dot-separated numbers (decryption parameters)
        # This matches: data-nx, data-xx, data-key, data-param, data-abc123, etc.
        param_match = re.search(r'data-([a-zA-Z][a-zA-Z0-9]*)\s*=\s*["\'](\d+\.\d+\.\d+\.\d+\.\d+\.\d+)["\']', self.content)
        if param_match:
            self.components['param_attr_name'] = f"data-{param_match.group(1)}"
            self.components['data_params'] = param_match.group(2)
        
        # Check for xlink:href Base64 payload (DNA variant)
        xlink_match = re.search(r'xlink:href="data:[^;]+;base64,([A-Za-z0-9+/=]+)"', self.content)
        if xlink_match:
            self.components['xlink_base64'] = xlink_match.group(1)
            try:
                decoded_js = base64.b64decode(xlink_match.group(1)).decode('utf-8', errors='ignore')
                # More flexible DNA pattern matching - allow ACGTU
                dna_match = re.search(r'var\s+\w+\s*=\s*["\']([ACGTU]{50,})\|([0-9a-fA-F]{8,})["\']', decoded_js)
                if dna_match:
                    self.components['dna_string'] = dna_match.group(1)
                    self.components['dna_params'] = dna_match.group(2)
            except:
                pass
        
        # window.dawa, window.owda or similar victim identifier patterns
        # Matches: window.dawa, window.owda, var owda, var dawa, etc.
        dawa_patterns = [
            r'window\.dawa\s*=\s*["\']([^"\']+)["\']',
            r'window\.owda\s*=\s*["\']([^"\']+)["\']',
            r'var\s+dawa\s*=\s*["\']([^"\']+)["\']',
            r'var\s+owda\s*=\s*["\']([^"\']+)["\']',
            r'window\.victim\s*=\s*["\']([^"\']+)["\']',
            r'window\.target\s*=\s*["\']([^"\']+)["\']',
            r'window\.email\s*=\s*["\']([^"\']+)["\']',
            r'window\.[a-zA-Z]+\s*=\s*["\']([#$][^"\']+)["\']',  # Any window.* with # or $ prefix
            r'var\s+\w+\s*=\s*["\']([#$][^"\']+)["\']',  # Any var with # or $ prefix
        ]
        
        for pattern in dawa_patterns:
            match = re.search(pattern, self.content)
            if match:
                self.components['dawa'] = match.group(1)
                break
        
        # Hex payloads in variables
        matches = re.findall(r'var\s+\w+\s*=\s*["\']([0-9a-fA-F]{100,})["\']', self.content)
        if matches:
            self.components['hex_payloads'] = matches
        
        # Decode victim email if present
        if 'dawa' in self.components:
            decoded_email = self.base64_decoder.decode(self.components['dawa'])
            if decoded_email and '@' in decoded_email:
                self.components['victim_email'] = decoded_email
        
        return self.components
    
    def decode_payload(self):
        """Decode the payload based on detected type"""
        decoded_results = []
        
        # Try Type 4: Dual-Key XOR
        result = self.dual_key_xor.decode(self.content)
        if result:
            decoded_results.append({
                'type': 'Base64 + Dual-Key XOR',
                'payload': result,
                'key_info': self.dual_key_xor.key_info
            })
            # Also capture victim if found
            if self.dual_key_xor.params and self.dual_key_xor.params.get('victim'):
                self.components['victim_email'] = self.dual_key_xor.params['victim']
        
        # Try Type 3: DNA + Fibonacci
        if 'dna_string' in self.components and 'dna_params' in self.components:
            result = self.dna_fibonacci.decode(self.content)
            if result:
                decoded_results.append({
                    'type': 'DNA Encoding + Fibonacci XOR',
                    'payload': result,
                    'key_info': self.dna_fibonacci.key_info
                })
        
        # Try Type 2: LCG + Feistel
        if 'data_t' in self.components and 'data_params' in self.components:
            result = self.lcg_feistel.decode(
                self.components['data_t'],
                self.components['data_params']
            )
            if result:
                decoded_results.append({
                    'type': 'LCG + Feistel Cipher',
                    'payload': result,
                    'key_info': self.lcg_feistel.key_info
                })
        
        # Try Type 1: Simple XOR
        if 'hex_payloads' in self.components:
            for hex_payload in self.components['hex_payloads']:
                result = self.simple_xor.decode(hex_payload, self.content)
                if result:
                    decoded_results.append({
                        'type': 'Simple XOR',
                        'payload': result,
                        'key_info': self.simple_xor.key_info
                    })
        
        # Try character array extraction
        char_results = self.char_array.decode(self.content)
        if char_results:
            for result in char_results:
                if 'http' in result.lower() or len(result) > 20:
                    decoded_results.append({
                        'type': 'Character Array',
                        'payload': result,
                        'key_info': self.char_array.key_info
                    })
        
        if decoded_results:
            self.decoded_payload = decoded_results[0]['payload']
            self.key_info = decoded_results[0]['key_info']
        
        return decoded_results
    
    def extract_iocs(self):
        """Extract IOCs from decoded payload"""
        if not self.decoded_payload:
            return {}
        
        payload = self.decoded_payload
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s\'"<>\)]+', payload)
        
        # Reconstruct URLs from character arrays
        char_urls = self.char_array.decode(payload)
        if char_urls:
            for url in char_urls:
                if url.startswith('http'):
                    urls.append(url)
        
        # Try to decode atob() Base64 strings to find hidden URLs
        # Pattern: atob(`xxx`+'yyy'+...)
        atob_match = re.search(r'atob\s*\(\s*([`"\'][^`"\']+[`"\']\s*\+?\s*)+\)', payload)
        if atob_match:
            # Extract all the string parts
            parts = re.findall(r'[`"\']([^`"\']+)[`"\']', atob_match.group(0))
            if parts:
                combined = ''.join(parts)
                try:
                    decoded_url = base64.b64decode(combined).decode('utf-8', errors='ignore')
                    if decoded_url.startswith('http'):
                        urls.append(decoded_url)
                except:
                    pass
        
        # Extract domains
        domains = set()
        for url in urls:
            match = re.search(r'https?://([^/\s]+)', url)
            if match:
                domains.add(match.group(1))
        
        domains = {d for d in domains if d not in ['www.w3.org', 'w3.org']}
        
        self.iocs = {
            'urls': list(set(urls)),
            'domains': list(domains),
            'victim_email': self.components.get('victim_email', None)
        }
        
        return self.iocs
    
    def analyze_behavior(self):
        """Analyze malicious behaviors"""
        if not self.decoded_payload:
            return []
        
        payload = self.decoded_payload
        behaviors = []
        
        checks = [
            ('fetch(', 'C2_COMMUNICATION', 'Fetches content from remote server', 'HIGH'),
            ('XMLHttpRequest', 'C2_COMMUNICATION', 'Makes HTTP requests', 'HIGH'),
            ('location.href', 'REDIRECT', 'Redirects browser to malicious URL', 'HIGH'),
            ('location=', 'REDIRECT', 'Redirects browser to malicious URL', 'HIGH'),
            ('window.location', 'REDIRECT', 'Redirects browser to malicious URL', 'HIGH'),
            ('createElement', 'DOM_MANIPULATION', 'Creates DOM elements dynamically', 'MEDIUM'),
            ('appendChild', 'SCRIPT_INJECTION', 'Injects elements into page', 'HIGH'),
            ('iframe', 'IFRAME_INJECTION', 'Creates iframe for content injection', 'HIGH'),
            ('eval(', 'CODE_EXECUTION', 'Uses eval() for code execution', 'CRITICAL'),
            ('Function(', 'CODE_EXECUTION', 'Uses Function() for code execution', 'CRITICAL'),
            ('document.write', 'DOM_MANIPULATION', 'Writes directly to document', 'MEDIUM'),
            ('localStorage', 'DATA_ACCESS', 'Accesses local storage', 'LOW'),
            ('cookie', 'DATA_ACCESS', 'Accesses cookies', 'MEDIUM'),
            ('password', 'CREDENTIAL_THEFT', 'References password field', 'CRITICAL'),
            ('login', 'CREDENTIAL_THEFT', 'References login functionality', 'HIGH'),
            ('credential', 'CREDENTIAL_THEFT', 'References credentials', 'CRITICAL'),
            ('atob(', 'OBFUSCATION', 'Uses Base64 decoding', 'MEDIUM'),
        ]
        
        for pattern, behavior_type, description, severity in checks:
            if pattern.lower() in payload.lower():
                behaviors.append({
                    'type': behavior_type,
                    'description': description,
                    'severity': severity,
                    'pattern': pattern
                })
        
        self.behaviors = behaviors
        return behaviors
    
    def check_file_drop(self):
        """Check for file drop indicators"""
        if not self.decoded_payload:
            return []
        
        indicators = []
        payload = self.decoded_payload.lower()
        
        file_patterns = [
            ('blob:', 'Creates Blob object for binary data'),
            ('createobjecturl', 'Creates downloadable URL'),
            ('download', 'Download attribute/function detected'),
            ('filesaver', 'FileSaver library detected'),
            ('writefile', 'File write operation'),
            ('.exe', 'References executable file'),
            ('.dll', 'References DLL file'),
            ('.bat', 'References batch file'),
            ('.ps1', 'References PowerShell script'),
            ('.vbs', 'References VBScript'),
            ('.js', 'References JavaScript file'),
            ('.hta', 'References HTA file'),
        ]
        
        for pattern, description in file_patterns:
            if pattern in payload:
                indicators.append({'pattern': pattern, 'description': description})
        
        return indicators
    
    def generate_summary(self):
        """Generate a short executive summary of the analysis"""
        summary_lines = []
        
        # Encryption type
        if self.key_info:
            enc_type = self.key_info.type
        else:
            enc_type = "Unknown"
        
        # Victim
        victim = self.components.get('victim_email', 'Not identified')
        
        # C2 info
        c2_domains = self.iocs.get('domains', [])
        c2_urls = self.iocs.get('urls', [])
        
        # Build summary
        summary_lines.append("QUICK SUMMARY")
        summary_lines.append("─" * 40)
        summary_lines.append(f"  Encryption: {enc_type}")
        summary_lines.append(f"  Victim: {victim}")
        
        if c2_domains:
            summary_lines.append(f"  C2 Domain: {c2_domains[0]}")
        if c2_urls:
            # Filter out w3.org URLs
            real_urls = [u for u in c2_urls if 'w3.org' not in u]
            if real_urls:
                summary_lines.append(f"  C2 URL: {real_urls[0]}")
        
        # Attack type
        if self.decoded_payload:
            if 'location.href' in self.decoded_payload or 'location=' in self.decoded_payload:
                summary_lines.append(f"  Attack Type: Redirect to phishing page")
            elif 'fetch(' in self.decoded_payload:
                summary_lines.append(f"  Attack Type: Stage 2 loader (downloads payload)")
            elif 'createElement' in self.decoded_payload:
                summary_lines.append(f"  Attack Type: Script injection")
            else:
                summary_lines.append(f"  Attack Type: Credential phishing")
        
        summary_lines.append(f"  Verdict: 🔴 MALICIOUS")
        summary_lines.append("")
        
        return '\n'.join(summary_lines)
    
    def generate_report(self, raw_output=False):
        """Generate analysis report"""
        
        if raw_output:
            if self.decoded_payload:
                return self.decoded_payload
            return "No payload decoded"
        
        report = []
        
        report.append(f"\n{'═'*80}")
        report.append(f" STICKY AFROHEAD - SVG MALWARE ANALYSIS REPORT")
        report.append(f" {__tagline__}")
        report.append(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"{'═'*80}\n")
        
        # File info
        report.append(f"{'─'*80}")
        report.append(f" FILE INFORMATION")
        report.append(f"{'─'*80}")
        report.append(f"   Filename: {Path(self.filepath).name}")
        report.append(f"   Size: {len(self.content)} bytes\n")
        
        # Malware type
        report.append(f"{'─'*80}")
        report.append(f" MALWARE TYPE DETECTED")
        report.append(f"{'─'*80}")
        for mtype in self.malware_type:
            report.append(f"   • {mtype}")
        report.append("")
        
        # Components
        report.append(f"{'─'*80}")
        report.append(f" EXTRACTED COMPONENTS")
        report.append(f"{'─'*80}")
        if 'data_t' in self.components:
            report.append(f"   • Payload (data-t): {len(self.components['data_t'])} hex chars ({len(self.components['data_t'])//2} bytes)")
        if 'param_attr_name' in self.components:
            report.append(f"   • Parameters ({self.components['param_attr_name']}): {self.components['data_params']}")
        if 'dawa' in self.components:
            dawa_display = self.components['dawa'][:50] + '...' if len(self.components['dawa']) > 50 else self.components['dawa']
            report.append(f"   • Victim ID (raw): {dawa_display}")
        if 'victim_email' in self.components:
            report.append(f"   • Victim Email: {self.components['victim_email']}")
        report.append("")
        
        # Encryption key
        report.append(f"{'─'*80}")
        report.append(f" ENCRYPTION / XOR KEY INFORMATION")
        report.append(f"{'─'*80}")
        if self.key_info:
            report.append(f"   Type: {self.key_info.type}")
            report.append(f"   Value: {self.key_info.value}")
            report.append(f"   Source: {self.key_info.source}")
            if self.key_info.bytes:
                report.append(f"   Details:")
                for detail in self.key_info.bytes:
                    report.append(f"     • {detail}")
        report.append("")
        
        # Decoded payload
        report.append(f"{'─'*80}")
        report.append(f" DECODED PAYLOAD")
        report.append(f"{'─'*80}")
        if self.decoded_payload:
            report.append(f"\n{self.decoded_payload}\n")
        else:
            report.append("   No payload decoded")
        report.append("")
        
        # IOCs
        report.append(f"{'─'*80}")
        report.append(f" INDICATORS OF COMPROMISE (IOCs)")
        report.append(f"{'─'*80}")
        if self.iocs.get('domains'):
            report.append(f"   C2 Domains:")
            for domain in self.iocs['domains']:
                report.append(f"     → {domain}")
        if self.iocs.get('urls'):
            report.append(f"   URLs:")
            for url in self.iocs['urls']:
                if 'w3.org' not in url:
                    report.append(f"     → {url}")
        if self.iocs.get('victim_email'):
            report.append(f"   Victim: {self.iocs['victim_email']}")
        report.append("")
        
        # Behaviors
        report.append(f"{'─'*80}")
        report.append(f" MALICIOUS BEHAVIORS")
        report.append(f"{'─'*80}")
        for behavior in self.behaviors:
            severity_icon = "🔴" if behavior['severity'] in ['HIGH', 'CRITICAL'] else "🟡"
            report.append(f"   {severity_icon} [{behavior['severity']}] {behavior['type']}")
            report.append(f"      └─ {behavior['description']}")
        if not self.behaviors:
            report.append(f"   No behaviors detected")
        report.append("")
        
        # File drop
        file_drops = self.check_file_drop()
        report.append(f"{'─'*80}")
        report.append(f" FILE DROP ANALYSIS")
        report.append(f"{'─'*80}")
        if file_drops:
            for indicator in file_drops:
                report.append(f"   ⚠️  {indicator['pattern']}: {indicator['description']}")
        else:
            report.append(f"   ✓ No direct file drop indicators in this stage")
            report.append(f"   ℹ️  Note: This is a LOADER - Stage 2 may have more functionality")
        report.append("")
        
        # Verdict
        report.append(f"{'─'*80}")
        report.append(f" VERDICT")
        report.append(f"{'─'*80}")
        report.append(f"   🔴 MALICIOUS - Credential Phishing Loader")
        report.append("")
        
        # Quick Summary
        report.append(f"{'─'*80}")
        summary = self.generate_summary()
        report.append(summary)
        
        report.append(f"{'═'*80}")
        report.append(f" Analysis by {__author__}")
        report.append(f" {__team__}")
        report.append(f"{'═'*80}\n")
        
        return '\n'.join(report)

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f'Sticky Afrojack SVG Decoder - {__tagline__}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
    python3 {Path(__file__).name} malware.svg
    python3 {Path(__file__).name} malware.svg -o report.txt
    python3 {Path(__file__).name} malware.svg --raw > payload.js

{__team__}
        """
    )
    parser.add_argument('file', help='SVG file to analyze')
    parser.add_argument('-o', '--output', help='Save report to file')
    parser.add_argument('--raw', action='store_true', help='Output only decoded payload')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='SVG Decoder')
    
    args = parser.parse_args()
    
    # Only show banner if not raw output
    if not args.raw:
        banner()
    
    analyzer = SVGMalwareAnalyzer(args.file)
    
    if not analyzer.load_file():
        sys.exit(1)
    
    if not args.raw:
        print(f"{Colors.GREEN}[*] Analyzing: {args.file}{Colors.END}")
        
        print(f"\n{Colors.CYAN}[STEP 1] Detecting malware type...{Colors.END}")
        types = analyzer.detect_malware_type()
        for t in types:
            print(f"  {Colors.YELLOW}• {t}{Colors.END}")
        
        print(f"\n{Colors.CYAN}[STEP 2] Extracting components...{Colors.END}")
        components = analyzer.extract_components()
        for key, value in components.items():
            if isinstance(value, str) and len(value) > 50:
                print(f"  {Colors.GREEN}• {key}: {value[:50]}...{Colors.END}")
            elif isinstance(value, list):
                print(f"  {Colors.GREEN}• {key}: [{len(value)} items]{Colors.END}")
            else:
                print(f"  {Colors.GREEN}• {key}: {value}{Colors.END}")
        
        print(f"\n{Colors.CYAN}[STEP 3] Decoding payload...{Colors.END}")
        results = analyzer.decode_payload()
        if results:
            print(f"  {Colors.GREEN}✓ Payload decoded successfully!{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ Failed to decode payload{Colors.END}")
        
        print(f"\n{Colors.CYAN}[STEP 4] Extracting IOCs...{Colors.END}")
        iocs = analyzer.extract_iocs()
        
        print(f"\n{Colors.CYAN}[STEP 5] Analyzing behaviors...{Colors.END}")
        behaviors = analyzer.analyze_behavior()
        
        report = analyzer.generate_report(raw_output=False)
        print(report)
    else:
        # Raw mode - silent processing
        analyzer.detect_malware_type()
        analyzer.extract_components()
        analyzer.decode_payload()
        
        # Output only the decoded payload
        if analyzer.decoded_payload:
            print(analyzer.decoded_payload)
        else:
            print("# Error: Could not decode payload")
    
    if args.output and not args.raw:
        with open(args.output, 'w') as f:
            clean_report = re.sub(r'\033\[[0-9;]*m', '', analyzer.generate_report())
            f.write(clean_report)
        print(f"{Colors.GREEN}[+] Report saved to: {args.output}{Colors.END}")

if __name__ == '__main__':
    main()
