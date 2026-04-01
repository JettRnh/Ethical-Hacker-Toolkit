#!/usr/bin/env python3
"""
Ethical Hacker Toolkit - Setup Script
Author: Jet
GitHub: https://github.com/JettRnh
"""

from setuptools import setup, find_packages

setup(
    name="ethical-hacker-toolkit",
    version="1.0.0",
    description="Professional Security Testing Framework for Authorized Penetration Testing",
    author="Jet",
    author_email="jet@security.test",
    url="https://github.com/JettRnh/ethical-hacker-toolkit",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "dnspython>=2.3.0",
        "colorama>=0.4.6",
        "whois>=0.9.27",
        "paramiko>=3.0.0",
        "scapy>=2.5.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "eht=eht:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
