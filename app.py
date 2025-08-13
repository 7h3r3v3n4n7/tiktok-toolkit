#!/usr/bin/env python3
"""
TikTok Toolkit - Main Application

A desktop application for TikTok API authentication and data scraping.
This application provides a GUI for TikTok OAuth authentication and API testing.

Features:
- TikTok OAuth 2.0 authentication with PKCE
- API testing and data retrieval
- Token management and refresh
- Privacy analysis and exposure detection
- Video metadata extraction and forensics

Usage:
    python main.py
"""

import sys
import os
from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget
from logger import logger

from tabs import AuthTab, PrivacyTab, ForensicsTab, ImpersonationTab, AnomalyTab, StalkerwareTab


class TikTokToolkit(QMainWindow):
    """TikTok Login Kit Desktop Application"""
    
    def __init__(self):
        super().__init__()
        self.access_token = None
        self.refresh_token = None
        
        logger.debug("APP", "Initializing TikTok Toolkit application")
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        logger.debug("APP", "Setting up user interface")
        self.setWindowTitle("TikTok Toolkit - Cybersecurity Analysis")
        self.setGeometry(100, 100, 1000, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Create tab components
        self.auth_tab = AuthTab(self)
        self.privacy_tab = PrivacyTab(self)
        self.forensics_tab = ForensicsTab(self)
        self.impersonation_tab = ImpersonationTab(self)
        self.anomaly_tab = AnomalyTab(self)
        self.stalkerware_tab = StalkerwareTab(self)

        # Add tabs
        tabs.addTab(self.auth_tab, "🔐 Authentication")
        tabs.addTab(self.privacy_tab, "🛡️ Privacy Analysis")
        tabs.addTab(self.forensics_tab, "🔍 Video Forensics")
        tabs.addTab(self.impersonation_tab, "🕵️ Impersonation Monitor")
        tabs.addTab(self.anomaly_tab, "🤖 Anomaly Detector")
        tabs.addTab(self.stalkerware_tab, "🕵️ Stalkerware Warning Tool")
        
        logger.debug("APP", "All tabs initialized and added to interface")
    
    def closeEvent(self, event):
        """Handle application close"""
        logger.debug("APP", "Application closing, cleaning up resources")
        if hasattr(self.auth_tab, 'auth_server') and self.auth_tab.auth_server:
            self.auth_tab.auth_server.stop()
        event.accept()