#!/usr/bin/env python3
"""
Adaptive threading utilities for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import os
import sys
import platform

def get_system_info():
    """Get system capability information"""
    info = {
        "cpu_count": os.cpu_count() or 4,
        "system": platform.system(),
        "machine": platform.machine()
    }
    
    # Detect if running in limited environment (Termux, WSL, etc.)
    is_limited = False
    if "android" in platform.platform().lower():
        is_limited = True
    elif "termux" in os.environ.get("PREFIX", ""):
        is_limited = True
    elif "Microsoft" in platform.uname().release:
        is_limited = True  # WSL
    
    info["is_limited"] = is_limited
    return info

def get_max_safe_threads(base_limit=500):
    """
    Calculate safe maximum threads based on system capabilities
    Returns the same base_limit if detection fails (safe fallback)
    """
    try:
        info = get_system_info()
        cpu_count = info["cpu_count"]
        
        # For limited environments (Termux, mobile, WSL)
        if info["is_limited"]:
            # Use more conservative limits
            return min(base_limit, cpu_count * 5, 200)
        
        # For normal desktop/server
        # I/O bound tasks can handle more threads
        return min(base_limit, cpu_count * 10, 1000)
        
    except Exception:
        # If anything fails, return original limit (safe fallback)
        return base_limit

def adapt_thread_count(requested, max_limit=500):
    """
    Take requested thread count and return safe adapted value
    This is the main function other modules should call
    
    Args:
        requested: Number of threads user requested
        max_limit: Absolute maximum cap
    
    Returns:
        Safe thread count
    """
    if requested is None:
        requested = 100  # Default
    
    # Get safe max from system
    safe_max = get_max_safe_threads(max_limit)
    
    # Never exceed safe max
    return min(requested, safe_max)

def get_recommended_threads(task_type="network"):
    """
    Get recommended thread count based on task type
    task_type: "network", "web", "crypto", "default"
    """
    info = get_system_info()
    cpu_count = info["cpu_count"]
    
    if info["is_limited"]:
        # Conservative for limited environments
        return 50
    
    # Different tasks have different optimal thread counts
    recommendations = {
        "network": cpu_count * 5,   # Network I/O heavy
        "web": cpu_count * 8,       # Web requests, more waiting
        "crypto": cpu_count * 2,    # CPU intensive
        "default": cpu_count * 5
    }
    
    result = recommendations.get(task_type, recommendations["default"])
    return min(result, 300)  # Cap at 300
