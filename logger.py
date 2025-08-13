"""
Logging utility for TikTok Toolkit
Provides debug logging that respects the DEBUG environment variable
"""

import os
from datetime import datetime
from typing import Optional


class Logger:
    """Simple logging class for debug output"""
    
    _instance = None
    _debug_enabled = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._debug_enabled is None:
            # Check if DEBUG is enabled in environment
            debug_env = os.getenv('DEBUG', 'False').lower()
            self._debug_enabled = debug_env in ('true', '1', 'yes', 'on')
    
    def debug(self, tag: str, message: str, data: Optional[dict] = None):
        """Print debug message if DEBUG is enabled"""
        if not self._debug_enabled:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Format the message
        formatted_message = f"[{timestamp}] {tag}: {message}"
        
        # Add data if provided
        if data:
            formatted_message += f" | Data: {data}"
        
        print(formatted_message)
    
    def info(self, tag: str, message: str, data: Optional[dict] = None):
        """Print info message (always shown)"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_message = f"[{timestamp}] {tag}: {message}"
        
        if data:
            formatted_message += f" | Data: {data}"
        
        print(formatted_message)
    
    def error(self, tag: str, message: str, error: Optional[Exception] = None):
        """Print error message (always shown)"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_message = f"[{timestamp}] {tag}: ERROR - {message}"
        
        if error:
            formatted_message += f" | Exception: {error}"
        
        print(formatted_message)
    
    def warning(self, tag: str, message: str, data: Optional[dict] = None):
        """Print warning message (always shown)"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_message = f"[{timestamp}] {tag}: WARNING - {message}"
        
        if data:
            formatted_message += f" | Data: {data}"
        
        print(formatted_message)


# Global logger instance
logger = Logger()
