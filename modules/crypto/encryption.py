#!/usr/bin/env python3
"""
Encryption module for encoding/decoding and crypto operations
Author: Jet
GitHub: https://github.com/JettRnh
"""

import base64
import hashlib
import os
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from core.logger import log

class Encryption:
    """Encryption and encoding utilities"""
    
    def __init__(self):
        log.status("Encryption module initialized")
    
    # Base64 operations
    def base64_encode(self, text):
        """Encode text to base64"""
        try:
            encoded = base64.b64encode(text.encode()).decode()
            return encoded
        except Exception as e:
            log.error(f"Base64 encode error: {e}")
            return None
    
    def base64_decode(self, encoded):
        """Decode base64 to text"""
        try:
            decoded = base64.b64decode(encoded).decode()
            return decoded
        except Exception as e:
            log.error(f"Base64 decode error: {e}")
            return None
    
    # Hex operations
    def hex_encode(self, text):
        """Encode text to hex"""
        try:
            encoded = binascii.hexlify(text.encode()).decode()
            return encoded
        except Exception as e:
            log.error(f"Hex encode error: {e}")
            return None
    
    def hex_decode(self, encoded):
        """Decode hex to text"""
        try:
            decoded = binascii.unhexlify(encoded).decode()
            return decoded
        except Exception as e:
            log.error(f"Hex decode error: {e}")
            return None
    
    # URL encoding
    def url_encode(self, text):
        """URL encode text"""
        import urllib.parse
        return urllib.parse.quote(text)
    
    def url_decode(self, encoded):
        """URL decode text"""
        import urllib.parse
        return urllib.parse.unquote(encoded)
    
    # XOR encryption
    def xor_encrypt(self, text, key):
        """XOR encryption"""
        result = []
        for i, char in enumerate(text):
            key_char = key[i % len(key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        return ''.join(result)
    
    # ROT13
    def rot13(self, text):
        """ROT13 cipher"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    # Caesar cipher
    def caesar_cipher(self, text, shift):
        """Caesar cipher encryption"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    # Fernet symmetric encryption
    def generate_fernet_key(self):
        """Generate Fernet key"""
        return Fernet.generate_key().decode()
    
    def fernet_encrypt(self, text, key):
        """Encrypt with Fernet"""
        try:
            f = Fernet(key.encode())
            encrypted = f.encrypt(text.encode())
            return encrypted.decode()
        except Exception as e:
            log.error(f"Fernet encrypt error: {e}")
            return None
    
    def fernet_decrypt(self, encrypted, key):
        """Decrypt with Fernet"""
        try:
            f = Fernet(key.encode())
            decrypted = f.decrypt(encrypted.encode())
            return decrypted.decode()
        except Exception as e:
            log.error(f"Fernet decrypt error: {e}")
            return None
    
    # PBKDF2 key derivation
    def derive_key(self, password, salt=None, iterations=100000):
        """Derive key from password using PBKDF2"""
        if not salt:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode())
        return binascii.hexlify(key).decode(), binascii.hexlify(salt).decode()
    
    # Hash functions
    def hash_md5(self, text):
        return hashlib.md5(text.encode()).hexdigest()
    
    def hash_sha1(self, text):
        return hashlib.sha1(text.encode()).hexdigest()
    
    def hash_sha256(self, text):
        return hashlib.sha256(text.encode()).hexdigest()
    
    def hash_sha512(self, text):
        return hashlib.sha512(text.encode()).hexdigest()
    
    def get_report(self, text, key=None):
        """Generate encryption report for a given text"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("ENCRYPTION REPORT")
        lines.append("=" * 60)
        lines.append(f"Original Text: {text[:50]}...")
        lines.append("=" * 60)
        
        lines.append(f"\nBase64: {self.base64_encode(text)}")
        lines.append(f"Hex: {self.hex_encode(text)}")
        lines.append(f"URL Encoded: {self.url_encode(text)}")
        lines.append(f"ROT13: {self.rot13(text)}")
        lines.append(f"Caesar (shift 3): {self.caesar_cipher(text, 3)}")
        
        lines.append(f"\nMD5: {self.hash_md5(text)}")
        lines.append(f"SHA1: {self.hash_sha1(text)}")
        lines.append(f"SHA256: {self.hash_sha256(text)}")
        lines.append(f"SHA512: {self.hash_sha512(text)}")
        
        if key:
            fernet_key = self.generate_fernet_key()
            encrypted = self.fernet_encrypt(text, fernet_key)
            lines.append(f"\nFernet Key: {fernet_key}")
            lines.append(f"Fernet Encrypted: {encrypted}")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
