"""
Authentication Tab Component
Handles TikTok OAuth authentication and token management
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QProgressBar, QTextEdit, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
import requests
import json
import os
import secrets
import hashlib
import base64
import webbrowser
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs, unquote
from auth_server import TikTokAuthServer
from logger import logger


class AuthTab(QWidget):
    """Authentication tab for TikTok OAuth flow"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.auth_server = None
        self.client_key = "sbawqk6aeul7ds655k"  # Your TikTok app client key
        self.redirect_uri = "http://localhost:8080/callback/"
        self.access_token = None
        self.refresh_token = None
        self.token_expires_in = None
        self.code_verifier = None
        self.code_challenge = None
        
        self.setup_ui()
        self.load_saved_tokens()
    
    def setup_ui(self):
        """Setup the authentication UI"""
        layout = QVBoxLayout(self)
        
        # Redirect URI is hardcoded
        self.redirect_uri = "http://localhost:8080/callback/"
        
        # Authentication group
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)
        
        # Login button
        self.login_button = QPushButton("🔗 Login with TikTok")
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #fe2c55;
                color: white;
                border: none;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #e62a4d;
            }
            QPushButton:pressed {
                background-color: #d42845;
            }
        """)
        self.login_button.clicked.connect(self.start_oauth_flow)
        auth_layout.addWidget(self.login_button)
        
        # Status label
        self.status_label = QLabel("Ready to authenticate")
        self.status_label.setAlignment(Qt.AlignCenter)
        auth_layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        auth_layout.addWidget(self.progress_bar)
        
        layout.addWidget(auth_group)
        
        # Token display group
        token_group = QGroupBox("Access Token")
        token_layout = QVBoxLayout(token_group)
        
        self.token_display = QTextEdit()
        self.token_display.setMaximumHeight(100)
        self.token_display.setPlaceholderText("Access token will appear here after successful authentication")
        token_layout.addWidget(self.token_display)
        
        # Token actions
        token_actions = QHBoxLayout()
        
        self.refresh_token_button = QPushButton("🔄 Refresh Token")
        self.refresh_token_button.clicked.connect(self.refresh_access_token)
        token_actions.addWidget(self.refresh_token_button)
        
        self.clear_token_button = QPushButton("🗑️ Clear Token")
        self.clear_token_button.clicked.connect(self.clear_tokens)
        token_actions.addWidget(self.clear_token_button)
        
        token_layout.addLayout(token_actions)
        layout.addWidget(token_group)
    
    def start_oauth_flow(self):
        """Start the OAuth 2.0 flow with PKCE"""
        logger.debug("AUTH", "Starting OAuth flow...")
        try:
            self.status_label.setText("🔄 Starting OAuth flow...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            
            # Generate PKCE parameters
            self.generate_pkce_pair()
            logger.debug("AUTH", f"Generated PKCE - Verifier: {self.code_verifier[:10]}..., Challenge: {self.code_challenge[:10]}...")
            
            # Generate state parameter
            state = secrets.token_urlsafe(32)
            logger.debug("AUTH", f"Generated state: {state[:10]}...")
            
            # Build authorization URL
            auth_params = {
                'client_key': self.client_key,
                'response_type': 'code',
                'scope': 'user.info.basic,user.info.profile,user.info.stats,video.list',
                'redirect_uri': self.redirect_uri,
                'state': state,
                'code_challenge': self.code_challenge,
                'code_challenge_method': 'S256'
            }
            
            auth_url = f"https://www.tiktok.com/v2/auth/authorize/?{urlencode(auth_params)}"
            
            logger.debug("AUTH", f"Authorization URL: {auth_url}")
            
            # Start local server to handle callback
            self.auth_server = TikTokAuthServer()
            self.auth_server.callback_received.connect(self.handle_callback)
            self.auth_server.start()
            logger.debug("AUTH", "Started local auth server")
            
            # Open browser
            logger.debug("AUTH", "Opening browser for authentication...")
            webbrowser.open(auth_url)
            
            self.status_label.setText("🌐 Browser opened - complete authentication on TikTok")
            
        except Exception as e:
            self.status_label.setText(f"❌ Failed to start OAuth flow: {e}")
            self.progress_bar.setVisible(False)
            logger.error("AUTH", "Failed to start OAuth flow", e)
    
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters, A-Z, a-z, 0-9, -, ., _, ~)
        allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        self.code_verifier = ''.join(secrets.choice(allowed_chars) for _ in range(43))
        
        # Generate code challenge (SHA256 hash of verifier, hex encoded)
        challenge_bytes = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        self.code_challenge = challenge_bytes.hex()
    
    def handle_callback(self, callback_data):
        """Handle the OAuth callback"""
        logger.debug("AUTH", "Received OAuth callback")
        try:
            logger.debug("AUTH", f"Callback data: {callback_data}")
            
            # Validate callback
            if not self.validate_callback(callback_data):
                self.status_label.setText("❌ Invalid callback received")
                return
            
            # Exchange code for tokens
            self.exchange_code_for_tokens(callback_data['code'])
            
        except Exception as e:
            self.status_label.setText(f"❌ Callback handling error: {e}")
            logger.error("AUTH", "Callback handling error", e)
    
    def validate_callback(self, callback_data):
        """Validate the OAuth callback data"""
        logger.debug("AUTH", "Validating callback data...")
        required_fields = ['code', 'scopes', 'state']
        
        for field in required_fields:
            if field not in callback_data:
                logger.debug("AUTH", f"Missing required field: {field}")
                return False
        
        logger.debug("AUTH", "Callback validation passed")
        logger.debug("AUTH", f"Granted scopes: {callback_data['scopes']}")
        return True
    
    def exchange_code_for_tokens(self, auth_code):
        """Exchange authorization code for access token"""
        try:
            self.status_label.setText("🔄 Exchanging code for tokens...")
            
            # Clean the authorization code (remove any suffixes)
            clean_code = auth_code.split('*')[0] if '*' in auth_code else auth_code
            
            token_data = {
                'client_key': self.client_key,
                'client_secret': '',  # Not needed for PKCE flow
                'code': clean_code,
                'grant_type': 'authorization_code',
                'redirect_uri': self.redirect_uri,
                'code_verifier': self.code_verifier
            }
            
            logger.debug("AUTH", f"Token exchange request data: {token_data}")
            response = requests.post('https://open.tiktokapis.com/v2/oauth/token/', data=token_data)
            logger.debug("AUTH", f"Token exchange response status: {response.status_code}")
            
            if response.status_code == 200:
                token_info = response.json()
                logger.debug("AUTH", f"Token response: {token_info}")
                
                self.access_token = token_info['access_token']
                self.refresh_token = token_info['refresh_token']
                self.token_expires_in = token_info.get('expires_in', 86400)
                
                logger.debug("AUTH", f"Access token: {self.access_token}")
                
                self.update_token_display()
                self.save_tokens()
                
                self.status_label.setText("✅ Authentication successful!")
                self.progress_bar.setVisible(False)
                
                # Update parent's access token
                if self.parent:
                    self.parent.access_token = self.access_token
                    self.parent.refresh_token = self.refresh_token
                
            else:
                error_msg = f"Token exchange failed: {response.status_code} - {response.text}"
                logger.error("AUTH", f"Token exchange failed: {response.status_code}", Exception(error_msg))
                self.status_label.setText(f"❌ {error_msg}")
                self.progress_bar.setVisible(False)
                
        except Exception as e:
            error_msg = f"Token exchange error: {e}"
            logger.error("AUTH", "Token exchange error", e)
            self.status_label.setText(f"❌ {error_msg}")
            self.progress_bar.setVisible(False)
    
    def refresh_access_token(self):
        """Refresh the access token using refresh token"""
        if not self.refresh_token:
            QMessageBox.warning(self, "No Refresh Token", "No refresh token available. Please authenticate first.")
            return
        
        try:
            self.status_label.setText("🔄 Refreshing access token...")
            print("🔄 Attempting token refresh...")
            
            refresh_data = {
                'client_key': self.client_key,
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            }
            
            response = requests.post('https://open.tiktokapis.com/v2/oauth/token/', data=refresh_data)
            
            if response.status_code == 200:
                token_info = response.json()
                
                self.access_token = token_info['access_token']
                self.refresh_token = token_info.get('refresh_token', self.refresh_token)
                self.token_expires_in = token_info.get('expires_in', 86400)
                
                self.update_token_display()
                self.save_tokens()
                
                self.status_label.setText("✅ Token refreshed successfully!")
                
                # Update parent's access token
                if self.parent:
                    self.parent.access_token = self.access_token
                    self.parent.refresh_token = self.refresh_token
                
            else:
                error_msg = f"Token refresh failed: {response.status_code} - {response.text}"
                self.status_label.setText(f"❌ {error_msg}")
                print(f"❌ {error_msg}")
                
        except Exception as e:
            error_msg = f"Token refresh error: {e}"
            self.status_label.setText(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
    
    def clear_tokens(self):
        """Clear saved tokens"""
        self.access_token = None
        self.refresh_token = None
        self.token_display.clear()
        self.save_tokens()
        self.status_label.setText("🗑️ Tokens cleared")
        
        # Update parent's tokens
        if self.parent:
            self.parent.access_token = None
            self.parent.refresh_token = None
    
    def save_tokens(self):
        """Save tokens to file"""
        tokens = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': getattr(self, 'token_expires_in', None),
            'saved_at': datetime.now().isoformat()
        }
        
        try:
            with open('tiktok_tokens.json', 'w') as f:
                json.dump(tokens, f, indent=2)
        except Exception as e:
            pass
    
    def load_saved_tokens(self):
        """Load saved tokens from file"""
        try:
            if os.path.exists('tiktok_tokens.json'):
                with open('tiktok_tokens.json', 'r') as f:
                    tokens = json.load(f)
                
                self.access_token = tokens.get('access_token')
                self.refresh_token = tokens.get('refresh_token')
                self.token_expires_in = tokens.get('expires_in')
                
                if self.access_token:
                    self.update_token_display()
                    self.status_label.setText("✅ Loaded saved tokens")
                    
                    # Update parent's tokens
                    if self.parent:
                        self.parent.access_token = self.access_token
                        self.parent.refresh_token = self.refresh_token
                    
        except Exception as e:
            pass
    
    def update_token_display(self):
        """Update the token display in the UI"""
        print(f"update_token_display called - access_token: {self.access_token}")  # Debug
        if hasattr(self, 'token_display') and self.access_token:
            print(f"Setting token display to: {self.access_token}")  # Debug
            self.token_display.setPlainText(self.access_token)
        else:
            print(f"Token display not updated - hasattr: {hasattr(self, 'token_display')}, access_token: {self.access_token}")  # Debug
