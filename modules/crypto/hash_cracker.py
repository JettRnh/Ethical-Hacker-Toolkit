#!/usr/bin/env python3
"""
Hash cracker module with multiple hash types and attack modes
Author: Jet
GitHub: https://github.com/JettRnh
"""

import hashlib
import threading
import time
from core.logger import log
from core.utils import ThreadPool

class HashCracker:
    """Password hash cracker with dictionary and brute-force attacks"""
    
    def __init__(self, target_hash, hash_type, wordlist=None, threads=50):
        self.target_hash = target_hash.lower()
        self.hash_type = hash_type.lower()
        self.wordlist = wordlist
        self.threads = min(threads, 200)
        self.found_password = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.running = True
        
        # Supported hash types
        self.hash_funcs = {
            'md5': hashlib.md5,
            'md4': lambda x: hashlib.new('md4', x.encode()),
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'ntlm': lambda x: hashlib.new('md4', x.encode('utf-16le'))
        }
        
        if hash_type not in self.hash_funcs:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        self.hash_func = self.hash_funcs[hash_type]
        
        log.status(f"HashCracker initialized for {hash_type} hash")
        log.info(f"Target hash: {target_hash[:32]}...")
    
    def hash_string(self, text):
        """Hash a string with selected algorithm"""
        try:
            return self.hash_func(text).hexdigest()
        except:
            return None
    
    def check_password(self, password):
        """Check if password matches hash"""
        hashed = self.hash_string(password)
        
        with self.lock:
            self.attempts += 1
        
        if hashed == self.target_hash:
            with self.lock:
                self.found_password = password
                self.running = False
            return True
        return False
    
    def dictionary_attack(self):
        """Attack using wordlist dictionary"""
        if not self.wordlist:
            log.error("No wordlist provided for dictionary attack")
            return None
        
        log.progress(f"Starting dictionary attack with {self.wordlist}")
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log.error(f"Wordlist not found: {self.wordlist}")
            return None
        
        log.info(f"Loaded {len(words)} words")
        
        pool = ThreadPool(self.threads)
        
        for word in words:
            if not self.running:
                break
            pool.submit(self.check_password, args=(word,))
        
        pool.wait()
        
        if self.found_password:
            log.success(f"Password found: {self.found_password}")
            log.info(f"Attempts: {self.attempts}")
        else:
            log.warning("Password not found in dictionary")
        
        return self.found_password
    
    def rule_based_attack(self, rules=None):
        """Attack with rules (append/prepend numbers, etc.)"""
        if not self.wordlist:
            log.error("No wordlist provided for rule-based attack")
            return None
        
        if rules is None:
            rules = ['append_numbers', 'prepend_numbers', 'leet_speak']
        
        log.progress(f"Starting rule-based attack with rules: {rules}")
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                base_words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log.error(f"Wordlist not found: {self.wordlist}")
            return None
        
        total_words = 0
        variations = []
        
        # Generate variations
        for word in base_words:
            variations.append(word)
            
            if 'append_numbers' in rules:
                for num in range(100):
                    variations.append(f"{word}{num}")
                    total_words += 1
            
            if 'prepend_numbers' in rules:
                for num in range(100):
                    variations.append(f"{num}{word}")
                    total_words += 1
            
            if 'leet_speak' in rules:
                leet = word.replace('a', '4').replace('e', '3').replace('i', '1')
                leet = leet.replace('o', '0').replace('s', '5')
                variations.append(leet)
        
        log.info(f"Generated {len(variations)} password variations")
        
        pool = ThreadPool(self.threads)
        
        for password in variations:
            if not self.running:
                break
            pool.submit(self.check_password, args=(password,))
        
        pool.wait()
        
        if self.found_password:
            log.success(f"Password found: {self.found_password}")
            log.info(f"Attempts: {self.attempts}")
        else:
            log.warning("Password not found with rules")
        
        return self.found_password
    
    def brute_force_attack(self, charset='abcdefghijklmnopqrstuvwxyz', max_length=4):
        """Brute force attack (very slow for longer passwords)"""
        log.warning(f"Brute force attack on {self.hash_type} hash (max length: {max_length})")
        log.warning("This may take a very long time")
        
        import itertools
        
        for length in range(1, max_length + 1):
            log.progress(f"Trying length {length}")
            
            for combo in itertools.product(charset, repeat=length):
                if not self.running:
                    break
                
                password = ''.join(combo)
                if self.check_password(password):
                    log.success(f"Password found: {password}")
                    return password
        
        log.warning("Password not found with brute force")
        return None
    
    def get_report(self):
        """Generate crack report"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("HASH CRACK REPORT")
        lines.append("=" * 60)
        lines.append(f"Hash Type: {self.hash_type}")
        lines.append(f"Target Hash: {self.target_hash}")
        lines.append(f"Attempts: {self.attempts}")
        lines.append(f"Result: {'FOUND' if self.found_password else 'NOT FOUND'}")
        
        if self.found_password:
            lines.append(f"Password: {self.found_password}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
