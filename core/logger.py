#!/usr/bin/env python3
"""
Logging module for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from config.settings import LOG_FILE, LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT

class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

class Logger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup_logger()
        return cls._instance
    
    def _setup_logger(self):
        self.logger = logging.getLogger("EHT")
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        
        # File handler
        file_handler = logging.FileHandler(LOG_FILE)
        file_format = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(file_format)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def _format_message(self, message, color=None):
        if color and sys.stdout.isatty():
            return f"{color}{message}{Colors.RESET}"
        return message
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        colored = self._format_message(message, Colors.YELLOW)
        self.logger.warning(colored)
    
    def error(self, message):
        colored = self._format_message(message, Colors.RED)
        self.logger.error(colored)
    
    def debug(self, message):
        colored = self._format_message(message, Colors.GRAY)
        self.logger.debug(colored)
    
    def success(self, message):
        colored = self._format_message(f"[+] {message}", Colors.GREEN)
        self.logger.info(colored)
    
    def progress(self, message):
        colored = self._format_message(f"[~] {message}", Colors.CYAN)
        self.logger.info(colored)
    
    def status(self, message):
        colored = self._format_message(f"[*] {message}", Colors.BLUE)
        self.logger.info(colored)
    
    def critical(self, message):
        colored = self._format_message(f"[!] {message}", Colors.MAGENTA)
        self.logger.critical(colored)

# Global logger instance
log = Logger()
