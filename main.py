#!/usr/bin/env python3
"""
TikTok Toolkit - Main Entry Point

A desktop application for TikTok API authentication and data scraping.
This is the main entry point for the TikTok toolkit application.

Usage:
    python main.py
"""

import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from logger import logger

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import TikTokToolkit


def main():
    """Main entry point for the TikTok Toolkit application"""
    
    logger.info("MAIN", "Starting TikTok Toolkit application")
    
    # Create the Qt application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("TikTok Toolkit")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("TikTok Toolkit")
    
    # Enable high DPI scaling
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # Create and show the main window
    logger.debug("MAIN", "Creating main application window")
    window = TikTokToolkit()
    window.show()
    
    logger.info("MAIN", "Application started successfully, entering event loop")
    # Start the application event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main() 