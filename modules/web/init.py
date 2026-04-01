#!/usr/bin/env python3
"""
Web modules package for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

from modules.web.dir_bruteforce import DirBruteforce
from modules.web.subdomain_enum import SubdomainEnum
from modules.web.headers_analyzer import HeadersAnalyzer
from modules.web.sql_injection import SQLInjection

__all__ = ['DirBruteforce', 'SubdomainEnum', 'HeadersAnalyzer', 'SQLInjection']
