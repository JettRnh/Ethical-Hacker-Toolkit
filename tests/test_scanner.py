#!/usr/bin/env python3
"""
Unit tests for scanner module
Author: Jet
GitHub: https://github.com/JettRnh
"""

import unittest
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner import BaseScanner
from core.utils import validate_ip, validate_port, resolve_hostname


class TestUtils(unittest.TestCase):
    """Test utility functions"""
    
    def test_validate_ip(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("notanip"))
    
    def test_validate_port(self):
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port(443))
        self.assertTrue(validate_port(1))
        self.assertTrue(validate_port(65535))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))
    
    def test_resolve_hostname(self):
        result = resolve_hostname("localhost")
        self.assertEqual(result, "127.0.0.1")
        
        result = resolve_hostname("nonexistent.domain.xyz")
        self.assertIsNone(result)


class TestScanner(unittest.TestCase):
    """Test scanner class"""
    
    def test_scanner_init(self):
        scanner = BaseScanner("localhost")
        self.assertEqual(scanner.ip, "127.0.0.1")
        self.assertEqual(scanner.target, "localhost")
    
    def test_scanner_invalid_target(self):
        with self.assertRaises(ValueError):
            BaseScanner("invalid.target.xyz")


if __name__ == "__main__":
    unittest.main()
