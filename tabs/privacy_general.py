"""
General Privacy Analysis Tab Component
Handles basic privacy score analysis and exposure risk detection
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QTextEdit, QMessageBox
)
import unicodedata
import requests
import json
import re
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingSpinner


class PrivacyGeneralTab(QWidget):
    """General Privacy Analysis tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
        # Initialize loading spinner
        self.loading_spinner = LoadingSpinner(self)
    
    def _norm_text(self, s: str) -> str:
        # fold unicode and common obfuscations: " at " " dot " etc.
        if not s: return ""
        s = unicodedata.normalize("NFKC", s)
        s = re.sub(r'\s*\(at\)\s*|\s+at\s+', '@', s, flags=re.I)
        s = re.sub(r'\s*\(dot\)\s*|\s+dot\s+', '.', s, flags=re.I)
        s = s.replace('[at]','@').replace('{at}','@').replace(' at ','@')
        s = s.replace('[dot]','.').replace('{dot}','.').replace(' dot ','.')
        return s

    def setup_ui(self):
        """Setup the general privacy analysis UI"""
        layout = QVBoxLayout(self)
        
        # Privacy Analysis group
        privacy_group = QGroupBox("General Privacy Analysis")
        privacy_layout = QVBoxLayout(privacy_group)
        
        # Analysis button
        self.analyze_privacy_button = QPushButton("Analyze Privacy & Exposure")
        self.analyze_privacy_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        self.analyze_privacy_button.clicked.connect(self.analyze_privacy_score)
        privacy_layout.addWidget(self.analyze_privacy_button)
        
        # Privacy score display
        score_layout = QHBoxLayout()
        score_layout.addWidget(QLabel("Privacy Score:"))
        self.privacy_score_label = QLabel("Not analyzed")
        self.privacy_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #666;")
        score_layout.addWidget(self.privacy_score_label)
        score_layout.addStretch()
        privacy_layout.addLayout(score_layout)
        
        # Analysis results
        self.privacy_results = QTextEdit()
        self.privacy_results.setPlaceholderText("Privacy analysis results will appear here...")
        self.privacy_results.setMaximumHeight(200)
        privacy_layout.addWidget(self.privacy_results)
        
        layout.addWidget(privacy_group)
        
        # Recommendations group
        recommendations_group = QGroupBox("Privacy Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_display = QTextEdit()
        self.recommendations_display.setPlaceholderText("Privacy recommendations will appear here...")
        self.recommendations_display.setMaximumHeight(200)
        recommendations_layout.addWidget(self.recommendations_display)
        
        layout.addWidget(recommendations_group)

    def _norm_text(self, s: str) -> str:
        # fold unicode and common obfuscations: “ at ” “ dot ” etc.
        if not s: return ""
        s = unicodedata.normalize("NFKC", s)
        s = re.sub(r'\s*\(at\)\s*|\s+at\s+', '@', s, flags=re.I)
        s = re.sub(r'\s*\(dot\)\s*|\s+dot\s+', '.', s, flags=re.I)
        s = s.replace('[at]','@').replace('{at}','@').replace(' at ','@')
        s = s.replace('[dot]','.').replace('{dot}','.').replace(' dot ','.')
        return s



    
    def get_access_token(self):
        """Get access token from main application"""
        logger.debug("PRIVACY_GENERAL", f"Parent hierarchy: parent={self.parent}, parent.parent={getattr(self.parent, 'parent', None) if self.parent else None}")
        if self.parent and hasattr(self.parent, 'parent') and self.parent.parent:
            token = self.parent.parent.access_token
            logger.debug("PRIVACY_GENERAL", f"Token from main app: {'Yes' if token else 'No'}")
            return token
        logger.debug("PRIVACY_GENERAL", "Could not access main application token")
        return None
    
    def analyze_privacy_score(self):
        """Analyze the user's privacy score and exposure risks based on profile data"""
        logger.debug("PRIVACY_GENERAL", "Starting privacy score analysis...")
        access_token = self.get_access_token()
        logger.debug("PRIVACY_GENERAL", f"Access token retrieved: {'Yes' if access_token else 'No'}")
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Analyzing Privacy Score", "Fetching user profile data...")
        self.analyze_privacy_button.setEnabled(False)
        
        try:
            self.privacy_results.clear()
            self.recommendations_display.clear()
            
            # Get user info first
            self.privacy_results.append("Fetching user profile data for privacy & exposure analysis...")
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            params = {
                'fields': 'open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count'
            }
            
            response = requests.get('https://open.tiktokapis.com/v2/user/info/', headers=headers, params=params)
            logger.debug("PRIVACY_GENERAL", f"API response status: {response.status_code}")
            
            if response.status_code == 200:
                user_data = response.json()
                logger.debug("PRIVACY_GENERAL", "Successfully retrieved user data")
                self.privacy_results.append("Successfully retrieved user data")
                
                # Analyze privacy score and exposure risks
                score, analysis, recommendations, exposure_risks = self.calculate_privacy_score(user_data)
                
                # Update UI
                self.privacy_score_label.setText(f"{score}/100")
                self.privacy_score_label.setStyleSheet(self.get_score_style(score))
                
                self.privacy_results.append(f"\nPrivacy Analysis:")
                for item in analysis:
                    self.privacy_results.append(f"• {item}")
                
                # Add exposure risks section
                if exposure_risks:
                    self.privacy_results.append(f"\nEXPOSURE RISKS DETECTED:")
                    for risk in exposure_risks:
                        self.privacy_results.append(f"• {risk}")
                
                self.recommendations_display.append("Privacy & Exposure Recommendations:")
                for rec in recommendations:
                    self.recommendations_display.append(f"• {rec}")
                    
            else:
                self.privacy_results.append(f"Error fetching user data: {response.status_code}")
                logger.debug("PRIVACY_GENERAL", f"API response: {response.text}")
                
        except Exception as e:
            logger.error("PRIVACY_GENERAL", "Exception during analysis", e)
            self.privacy_results.append(f"Exception during analysis: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.analyze_privacy_button.setEnabled(True)
    
    def calculate_privacy_score(self, user_data):
        logger.debug("PRIVACY_GENERAL", "Calculating privacy score...")
        score = 100
        analysis, recommendations, exposure_risks = [], [], []

        try:
            user = user_data.get('data', {}).get('user', {})
            display_name = user.get('display_name', '') or ''
            bio = user.get('bio_description', '') or ''
            follower_count = int(user.get('follower_count', 0) or 0)
            is_verified = bool(user.get('is_verified', False))
            video_count = int(user.get('video_count', 0) or 0)
            likes_count = int(user.get('likes_count', 0) or 0)

            # Display name checks
            analysis.append(f"Display name: '{display_name}'" if display_name else "Display name: (empty)")
            if len(display_name) > 28:
                score -= 3; recommendations.append("Shorten display name; long names often pack identifiers.")
            if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', display_name):
                score -= 12; exposure_risks.append("Email appears in display name.")
            if re.search(r'\d{4,}', display_name):  # long digit runs (birthyear, phone tail)
                score -= 4; recommendations.append("Avoid long digit runs in display name (looks like IDs).")

            # Bio checks with PII detection
            analysis.append(f"Bio: '{bio}'" if bio else "Bio: (empty)")
            pii = self.detect_pii(bio)
            if any(pii.values()):
                # penalties by category
                weights = {'email':12,'phone':10,'ssn':25,'cc':25,'url':3,'handle':1,'dob':8,'postal':4,'ip':4}
                for cat, items in pii.items():
                    if not items: continue
                    score -= min(20, weights.get(cat,2) * min(3, len(items)))
                    if cat in ('email','phone','ssn','cc','dob'):
                        exposure_risks.append(f"Bio contains {cat.upper()} ({len(items)})")
                    else:
                        recommendations.append(f"Review bio: found {cat} ({len(items)}).")
            elif len(bio) > 160:
                score -= 2; recommendations.append("Consider shortening bio; long bios leak context over time.")

            # Audience/visibility
            analysis.append(f"Followers: {follower_count:,}")
            if follower_count >= 100_000:
                score -= 10; exposure_risks.append("High visibility account (≥100k).")
            elif follower_count >= 10_000:
                score -= 6; recommendations.append("High audience increases OSINT surface; audit old posts.")
            elif follower_count >= 1_000:
                score -= 3

            # Verification
            analysis.append(f"Verified: {is_verified}")
            if is_verified: score -= 3

            # Content volume
            analysis.append(f"Videos: {video_count:,}")
            if video_count >= 500: score -= 6
            elif video_count >= 100: score -= 3

            # Engagement
            analysis.append(f"Total likes: {likes_count:,}")
            if likes_count >= 1_000_000: score -= 5
            elif likes_count >= 100_000: score -= 3

            # Clamp and summarize
            score = max(0, min(100, score))
            if score < 50:
                recommendations.append("Low privacy score — audit profile and content now.")
            elif score < 75:
                recommendations.append("Moderate privacy score — tighten profile details and review content.")
            else:
                recommendations.append("Good privacy baseline — continue periodic audits.")

            # Always-on hygiene
            recommendations += [
                "Enable 2FA and review active sessions.",
                "Limit contact details to business email via platform tools.",
                "Avoid real-time location and routine posting windows.",
                "Quarterly content audit: search your handle + phone/email on the open web."
            ]

            logger.debug("PRIVACY_GENERAL", f"Final privacy score: {score}/100")

        except Exception as e:
            logger.error("PRIVACY_GENERAL", "Error calculating privacy score", e)
            analysis.append(f"Error during analysis: {e}")
            score = 0

        return score, analysis, recommendations, exposure_risks
    
    def detect_pii(self, text: str) -> dict:
        """
        Returns {'email': [...], 'phone': [...], 'ssn': [...], 'cc': [...],
                'url': [...], 'handle': [...], 'dob': [...], 'postal': [...],
                'ip': [...]} with match spans and values.
        """
        out = {k: [] for k in ['email','phone','ssn','cc','url','handle','dob','postal','ip']}
        if not text: return out
        s = self._norm_text(text)

        # Email (obfuscations handled in _norm_text)
        for m in re.finditer(r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,253}\.[A-Za-z]{2,24}\b', s):
            out['email'].append((m.start(), m.end(), m.group()))

        # Phones (US + intl light) e.g. +1 212-555-1212, (212) 555-1212, 212.555.1212
        phone_rx = r'(?:(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,3}\d{2,4})'
        for m in re.finditer(phone_rx, s):
            val = re.sub(r'\D', '', m.group())
            if 10 <= len(val) <= 15:
                out['phone'].append((m.start(), m.end(), m.group()))

        # SSN (strict US)
        for m in re.finditer(r'\b\d{3}-\d{2}-\d{4}\b', s):
            out['ssn'].append((m.start(), m.end(), m.group()))

        # Credit Card (Luhn-validated)
        for m in re.finditer(r'\b(?:\d[ -]*?){13,19}\b', s):
            digits = re.sub(r'\D','', m.group())
            if 13 <= len(digits) <= 19 and self._luhn_ok(digits):
                out['cc'].append((m.start(), m.end(), m.group()))

        # URLs
        for m in re.finditer(r'https?://[^\s]+', s, re.I):
            out['url'].append((m.start(), m.end(), m.group()))

        # Handles (@name) not part of email
        for m in re.finditer(r'(?<!\w)@([A-Za-z0-9_]{2,32})', s):
            # skip if within an email span
            if not any(a <= m.start() <= b for a,b,_ in out['email']):
                out['handle'].append((m.start(), m.end(), m.group()))

        # Dates that look like DOBs (very basic)
        for m in re.finditer(r'\b(19\d{2}|20[0-2]\d)[-/\.](0?[1-9]|1[0-2])[-/\.](0?[1-9]|[12]\d|3[01])\b', s):
            out['dob'].append((m.start(), m.end(), m.group()))

        # US ZIP / ZIP+4 (don’t over-penalize but useful)
        for m in re.finditer(r'\b\d{5}(?:-\d{4})?\b', s):
            out['postal'].append((m.start(), m.end(), m.group()))

        # IP addresses (v4)
        for m in re.finditer(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b', s):
            out['ip'].append((m.start(), m.end(), m.group()))

        return out

    def _luhn_ok(self, s: str) -> bool:
        tot, alt = 0, False
        for d in s[::-1]:
            n = ord(d)-48
            if alt:
                n = n*2
                if n > 9: n -= 9
            tot += n
            alt = not alt
        return tot % 10 == 0

    
    def get_score_style(self, score):
        """Get CSS style for privacy score based on value"""
        if score >= 80:
            return "font-size: 18px; font-weight: bold; color: #4CAF50;"  # Green
        elif score >= 60:
            return "font-size: 18px; font-weight: bold; color: #FF9800;"  # Orange
        else:
            return "font-size: 18px; font-weight: bold; color: #F44336;"  # Red
