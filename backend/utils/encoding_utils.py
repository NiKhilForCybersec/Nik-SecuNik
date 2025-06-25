"""
Encoding Utilities - Character encoding detection and conversion
Handles various text encodings and binary data
"""

import chardet
import base64
import binascii
import codecs
import hashlib
import hmac
import re
from typing import Optional, Tuple, List, Dict, Any, Union
import magic
import unicodedata
from urllib.parse import quote, unquote, quote_plus, unquote_plus
import html
import json

class EncodingDetector:
    """Advanced encoding detection and conversion"""
    
    def __init__(self):
        # Common encodings to try
        self.common_encodings = [
            'utf-8', 'utf-16', 'utf-32',
            'ascii', 'latin-1', 'iso-8859-1',
            'windows-1252', 'cp1252',
            'gb2312', 'gbk', 'gb18030',  # Chinese
            'shift_jis', 'euc-jp',  # Japanese
            'euc-kr', 'cp949',  # Korean
            'koi8-r', 'windows-1251',  # Russian
            'iso-8859-2', 'windows-1250',  # Central European
        ]
        
        # BOM (Byte Order Mark) signatures
        self.bom_signatures = {
            b'\xef\xbb\xbf': 'utf-8-sig',
            b'\xff\xfe\x00\x00': 'utf-32-le',
            b'\x00\x00\xfe\xff': 'utf-32-be',
            b'\xff\xfe': 'utf-16-le',
            b'\xfe\xff': 'utf-16-be',
        }
        
        # Magic numbers for file types
        self.file_signatures = {
            b'\x89PNG': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'%PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',
            b'PK\x05\x06': 'application/zip',
            b'PK\x07\x08': 'application/zip',
            b'\x50\x4b\x03\x04': 'application/vnd.ms-office',
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/vnd.ms-office',
            b'MZ': 'application/x-executable',
            b'\x7fELF': 'application/x-elf',
        }
        
    def detect_encoding(
        self,
        data: bytes,
        confidence_threshold: float = 0.7
    ) -> Tuple[str, float]:
        """Detect encoding of byte data"""
        # Check for BOM
        bom_encoding = self._check_bom(data)
        if bom_encoding:
            return bom_encoding, 1.0
            
        # Use chardet for detection
        result = chardet.detect(data)
        
        if result['confidence'] >= confidence_threshold:
            return result['encoding'], result['confidence']
            
        # Try common encodings
        for encoding in self.common_encodings:
            try:
                data.decode(encoding)
                return encoding, 0.5  # Lower confidence for fallback
            except (UnicodeDecodeError, LookupError):
                continue
                
        # Default to latin-1 (can decode any byte sequence)
        return 'latin-1', 0.1
        
    def _check_bom(self, data: bytes) -> Optional[str]:
        """Check for BOM signature"""
        for bom, encoding in self.bom_signatures.items():
            if data.startswith(bom):
                return encoding
        return None
        
    def decode_safely(
        self,
        data: bytes,
        encoding: Optional[str] = None,
        errors: str = 'replace'
    ) -> str:
        """Safely decode bytes to string"""
        if not data:
            return ''
            
        # Auto-detect if no encoding specified
        if not encoding:
            encoding, _ = self.detect_encoding(data)
            
        try:
            # Remove BOM if present
            if encoding == 'utf-8-sig' or data.startswith(b'\xef\xbb\xbf'):
                data = data[3:] if data.startswith(b'\xef\xbb\xbf') else data
                encoding = 'utf-8'
                
            return data.decode(encoding, errors=errors)
        except (UnicodeDecodeError, LookupError):
            # Fallback to latin-1
            return data.decode('latin-1', errors='replace')
            
    def encode_safely(
        self,
        text: str,
        encoding: str = 'utf-8',
        errors: str = 'replace'
    ) -> bytes:
        """Safely encode string to bytes"""
        try:
            return text.encode(encoding, errors=errors)
        except (UnicodeEncodeError, LookupError):
            # Fallback to utf-8
            return text.encode('utf-8', errors='replace')
            
    def normalize_text(
        self,
        text: str,
        form: str = 'NFKC'
    ) -> str:
        """Normalize Unicode text"""
        # Forms: NFC, NFD, NFKC, NFKD
        return unicodedata.normalize(form, text)
        
    def clean_text(
        self,
        text: str,
        remove_control_chars: bool = True,
        normalize_whitespace: bool = True
    ) -> str:
        """Clean text by removing unwanted characters"""
        if remove_control_chars:
            # Remove control characters except newline and tab
            text = ''.join(
                char for char in text
                if char in '\n\t' or not unicodedata.category(char).startswith('C')
            )
            
        if normalize_whitespace:
            # Normalize whitespace
            text = re.sub(r'\s+', ' ', text)
            text = text.strip()
            
        return text
        
    def is_binary(self, data: bytes, sample_size: int = 8192) -> bool:
        """Check if data is binary or text"""
        # Sample the data
        sample = data[:sample_size]
        
        # Check for null bytes
        if b'\x00' in sample:
            return True
            
        # Check file signatures
        for signature in self.file_signatures:
            if sample.startswith(signature):
                return True
                
        # Use magic library if available
        try:
            mime_type = magic.from_buffer(sample, mime=True)
            return not mime_type.startswith('text/')
        except:
            pass
            
        # Heuristic: count non-printable characters
        non_printable = 0
        for byte in sample:
            if byte < 32 and byte not in (9, 10, 13):  # tab, newline, carriage return
                non_printable += 1
                
        # If more than 30% non-printable, consider binary
        return non_printable / len(sample) > 0.3
        
    def detect_file_type(self, data: bytes) -> Optional[str]:
        """Detect file type from data"""
        # Check file signatures
        for signature, mime_type in self.file_signatures.items():
            if data.startswith(signature):
                return mime_type
                
        # Use magic library
        try:
            return magic.from_buffer(data, mime=True)
        except:
            return None
            
    def to_hex(self, data: bytes, separator: str = ' ') -> str:
        """Convert bytes to hex string"""
        hex_str = binascii.hexlify(data).decode('ascii')
        
        if separator:
            # Add separator every 2 characters
            hex_str = separator.join(
                hex_str[i:i+2] for i in range(0, len(hex_str), 2)
            )
            
        return hex_str
        
    def from_hex(self, hex_str: str) -> bytes:
        """Convert hex string to bytes"""
        # Remove common separators
        hex_str = hex_str.replace(' ', '').replace(':', '').replace('-', '')
        
        try:
            return binascii.unhexlify(hex_str)
        except binascii.Error:
            # Try to fix odd-length hex strings
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            return binascii.unhexlify(hex_str)
            
    def to_base64(
        self,
        data: bytes,
        urlsafe: bool = False,
        no_padding: bool = False
    ) -> str:
        """Encode to base64"""
        if urlsafe:
            encoded = base64.urlsafe_b64encode(data)
        else:
            encoded = base64.b64encode(data)
            
        result = encoded.decode('ascii')
        
        if no_padding:
            result = result.rstrip('=')
            
        return result
        
    def from_base64(
        self,
        b64_str: str,
        urlsafe: bool = False
    ) -> bytes:
        """Decode from base64"""
        # Add padding if missing
        padding = 4 - (len(b64_str) % 4)
        if padding != 4:
            b64_str += '=' * padding
            
        try:
            if urlsafe:
                return base64.urlsafe_b64decode(b64_str)
            else:
                return base64.b64decode(b64_str)
        except:
            # Try the other variant
            if urlsafe:
                return base64.b64decode(b64_str)
            else:
                return base64.urlsafe_b64decode(b64_str)
                
    def url_encode(
        self,
        text: str,
        plus_spaces: bool = False,
        safe: str = ''
    ) -> str:
        """URL encode text"""
        if plus_spaces:
            return quote_plus(text, safe=safe)
        else:
            return quote(text, safe=safe)
            
    def url_decode(self, encoded: str, plus_spaces: bool = False) -> str:
        """URL decode text"""
        if plus_spaces:
            return unquote_plus(encoded)
        else:
            return unquote(encoded)
            
    def html_encode(self, text: str, quote: bool = True) -> str:
        """HTML encode text"""
        return html.escape(text, quote=quote)
        
    def html_decode(self, encoded: str) -> str:
        """HTML decode text"""
        return html.unescape(encoded)
        
    def detect_hash_type(self, hash_str: str) -> Optional[str]:
        """Detect hash algorithm from hash string"""
        hash_str = hash_str.strip().lower()
        
        # Remove common prefixes
        for prefix in ['$', '0x']:
            if hash_str.startswith(prefix):
                hash_str = hash_str[len(prefix):]
                
        # Check by length and pattern
        if re.match(r'^[a-f0-9]{32}$', hash_str):
            return 'md5'
        elif re.match(r'^[a-f0-9]{40}$', hash_str):
            return 'sha1'
        elif re.match(r'^[a-f0-9]{64}$', hash_str):
            return 'sha256'
        elif re.match(r'^[a-f0-9]{128}$', hash_str):
            return 'sha512'
        elif re.match(r'^[a-f0-9]{56}$', hash_str):
            return 'sha224'
        elif re.match(r'^[a-f0-9]{96}$', hash_str):
            return 'sha384'
        elif hash_str.startswith('$2a$') or hash_str.startswith('$2b$'):
            return 'bcrypt'
        elif hash_str.startswith('$6$'):
            return 'sha512crypt'
        elif hash_str.startswith('$5$'):
            return 'sha256crypt'
        elif hash_str.startswith('$1$'):
            return 'md5crypt'
            
        return None
        
    def calculate_hash(
        self,
        data: Union[str, bytes],
        algorithm: str = 'sha256'
    ) -> str:
        """Calculate hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.hexdigest()
        
    def calculate_hmac(
        self,
        key: Union[str, bytes],
        data: Union[str, bytes],
        algorithm: str = 'sha256'
    ) -> str:
        """Calculate HMAC of data"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        return hmac.new(key, data, algorithm).hexdigest()
        
    def rot13(self, text: str) -> str:
        """Apply ROT13 encoding"""
        return codecs.encode(text, 'rot_13')
        
    def xor_encode(
        self,
        data: bytes,
        key: bytes,
        repeat_key: bool = True
    ) -> bytes:
        """XOR encode data with key"""
        result = bytearray()
        
        if repeat_key:
            # Repeat key to match data length
            for i, byte in enumerate(data):
                result.append(byte ^ key[i % len(key)])
        else:
            # Single-byte XOR
            key_byte = key[0] if key else 0
            for byte in data:
                result.append(byte ^ key_byte)
                
        return bytes(result)
        
    def detect_obfuscation(self, text: str) -> Dict[str, Any]:
        """Detect common obfuscation techniques"""
        indicators = {
            'base64': False,
            'hex_encoding': False,
            'url_encoding': False,
            'unicode_escape': False,
            'excessive_escaping': False,
            'suspicious_patterns': []
        }
        
        # Check for base64
        if re.search(r'^[A-Za-z0-9+/]{20,}={0,2}$', text):
            indicators['base64'] = True
            
        # Check for hex encoding
        if re.search(r'^[0-9a-fA-F\s]{20,}$', text):
            indicators['hex_encoding'] = True
            
        # Check for URL encoding
        if text.count('%') > len(text) * 0.1:
            indicators['url_encoding'] = True
            
        # Check for unicode escapes
        if re.search(r'\\u[0-9a-fA-F]{4}', text):
            indicators['unicode_escape'] = True
            
        # Check for excessive escaping
        escape_count = text.count('\\')
        if escape_count > len(text) * 0.1:
            indicators['excessive_escaping'] = True
            
        # Check for suspicious patterns
        patterns = [
            (r'eval\s*\(', 'eval usage'),
            (r'exec\s*\(', 'exec usage'),
            (r'String\.fromCharCode', 'character code conversion'),
            (r'atob\s*\(', 'base64 decode'),
            (r'unescape\s*\(', 'unescape usage'),
            (r'\$\{.*\}', 'template literal evaluation'),
        ]
        
        for pattern, description in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators['suspicious_patterns'].append(description)
                
        return indicators
        
    def deobfuscate_basic(self, text: str) -> List[str]:
        """Attempt basic deobfuscation"""
        results = []
        
        # Try base64 decode
        try:
            if re.match(r'^[A-Za-z0-9+/]+=*$', text):
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                if decoded and decoded != text:
                    results.append(f"Base64 decoded: {decoded}")
        except:
            pass
            
        # Try hex decode
        try:
            hex_text = text.replace(' ', '').replace('\\x', '')
            if re.match(r'^[0-9a-fA-F]+$', hex_text) and len(hex_text) % 2 == 0:
                decoded = bytes.fromhex(hex_text).decode('utf-8', errors='ignore')
                if decoded and decoded != text:
                    results.append(f"Hex decoded: {decoded}")
        except:
            pass
            
        # Try URL decode
        try:
            if '%' in text:
                decoded = unquote(text)
                if decoded != text:
                    results.append(f"URL decoded: {decoded}")
        except:
            pass
            
        # Try unicode unescape
        try:
            if '\\u' in text:
                decoded = text.encode().decode('unicode-escape')
                if decoded != text:
                    results.append(f"Unicode unescaped: {decoded}")
        except:
            pass
            
        # Try ROT13
        try:
            decoded = codecs.decode(text, 'rot_13')
            if decoded != text:
                results.append(f"ROT13 decoded: {decoded}")
        except:
            pass
            
        return results


# Utility functions
def detect_encoding(data: bytes) -> Tuple[str, float]:
    """Detect encoding of byte data"""
    detector = EncodingDetector()
    return detector.detect_encoding(data)

def decode_safely(
    data: bytes,
    encoding: Optional[str] = None
) -> str:
    """Safely decode bytes to string"""
    detector = EncodingDetector()
    return detector.decode_safely(data, encoding)

def encode_safely(
    text: str,
    encoding: str = 'utf-8'
) -> bytes:
    """Safely encode string to bytes"""
    detector = EncodingDetector()
    return detector.encode_safely(text, encoding)

def is_binary(data: bytes) -> bool:
    """Check if data is binary"""
    detector = EncodingDetector()
    return detector.is_binary(data)

def to_hex(data: bytes, separator: str = ' ') -> str:
    """Convert bytes to hex string"""
    detector = EncodingDetector()
    return detector.to_hex(data, separator)

def from_hex(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    detector = EncodingDetector()
    return detector.from_hex(hex_str)

def to_base64(data: bytes, urlsafe: bool = False) -> str:
    """Encode to base64"""
    detector = EncodingDetector()
    return detector.to_base64(data, urlsafe)

def from_base64(b64_str: str, urlsafe: bool = False) -> bytes:
    """Decode from base64"""
    detector = EncodingDetector()
    return detector.from_base64(b64_str, urlsafe)

def normalize_text(text: str) -> str:
    """Normalize Unicode text"""
    detector = EncodingDetector()
    return detector.normalize_text(text)

def clean_text(text: str) -> str:
    """Clean text by removing unwanted characters"""
    detector = EncodingDetector()
    return detector.clean_text(text)

def url_encode(text: str, plus_spaces: bool = False) -> str:
    """URL encode text"""
    detector = EncodingDetector()
    return detector.url_encode(text, plus_spaces)

def url_decode(encoded: str, plus_spaces: bool = False) -> str:
    """URL decode text"""
    detector = EncodingDetector()
    return detector.url_decode(encoded, plus_spaces)

def html_encode(text: str) -> str:
    """HTML encode text"""
    detector = EncodingDetector()
    return detector.html_encode(text)

def html_decode(encoded: str) -> str:
    """HTML decode text"""
    detector = EncodingDetector()
    return detector.html_decode(encoded)

def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """Calculate hash of data"""
    detector = EncodingDetector()
    return detector.calculate_hash(data, algorithm)

def detect_hash_type(hash_str: str) -> Optional[str]:
    """Detect hash algorithm from hash string"""
    detector = EncodingDetector()
    return detector.detect_hash_type(hash_str)

def detect_obfuscation(text: str) -> Dict[str, Any]:
    """Detect common obfuscation techniques"""
    detector = EncodingDetector()
    return detector.detect_obfuscation(text)

def xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR encode data with key"""
    detector = EncodingDetector()
    return detector.xor_encode(data, key)