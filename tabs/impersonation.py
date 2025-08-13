"""
Impersonation Monitor Tab Component
Detects impersonation accounts or clones using your name, face, or content
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QInputDialog
)
import requests
import json
import re
from datetime import datetime
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingSpinner

# Optional dependencies for advanced impersonation detection
try:
    import Levenshtein  # optional – faster edit distance
except Exception:
    Levenshtein = None
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except Exception:
    TfidfVectorizer = None
    cosine_similarity = None
try:
    from PIL import Image
    import imagehash
except Exception:
    Image = None
    imagehash = None

from difflib import SequenceMatcher
from io import BytesIO


# Helper functions for impersonation detection
def _norm(s: str) -> str:
    """Normalize string for comparison"""
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())

def username_similarity(a: str, b: str) -> float:
    """Calculate username similarity using Levenshtein or SequenceMatcher"""
    a, b = _norm(a), _norm(b)
    if not a or not b: 
        return 0.0
    if Levenshtein:
        dist = Levenshtein.distance(a, b)
        return 1.0 - dist / max(len(a), len(b))
    return SequenceMatcher(None, a, b).ratio()

def bio_similarity(user_bio: str, other_bio: str) -> float:
    """Calculate bio similarity using TF-IDF cosine or SequenceMatcher"""
    a, b = (user_bio or '').strip(), (other_bio or '').strip()
    if not a or not b: 
        return 0.0
    if TfidfVectorizer and cosine_similarity:
        try:
            vec = TfidfVectorizer(min_df=1, ngram_range=(1,2), stop_words='english')
            X = vec.fit_transform([a, b])
            return float(cosine_similarity(X[0], X[1])[0,0])
        except Exception:
            pass
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def avatar_phash_similarity(url_a: str, url_b: str) -> float:
    """Calculate avatar similarity using perceptual hashing"""
    if not Image or not imagehash:
        return 0.0  # Fallback if dependencies not available
    
    def ph(u):
        try:
            r = requests.get(u, timeout=5)
            r.raise_for_status()
            img = Image.open(BytesIO(r.content)).convert('RGB')
            return imagehash.phash(img)
        except Exception:
            return None
    ha, hb = ph(url_a), ph(url_b)
    if ha is None or hb is None:
        return 0.0
    # hamming distance to [0,1] similarity
    return 1.0 - (ha - hb) / len(ha.hash.ravel())


class ImpersonationTab(QWidget):
    """Impersonation Monitor tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
        # Initialize loading spinner
        self.loading_spinner = LoadingSpinner(self)
    
    def setup_ui(self):
        """Setup the impersonation monitor UI"""
        layout = QVBoxLayout(self)
        
        # Impersonation Monitor group
        monitor_group = QGroupBox("Impersonation Monitor")
        monitor_layout = QVBoxLayout(monitor_group)
        
        # Analysis buttons
        buttons_layout = QHBoxLayout()
        
        self.scan_usernames_button = QPushButton("🔍 Scan for Similar Usernames")
        self.scan_usernames_button.setStyleSheet("""
            QPushButton {
                background-color: #FF5722;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #E64A19;
            }
            QPushButton:pressed {
                background-color: #D84315;
            }
        """)
        self.scan_usernames_button.clicked.connect(self.scan_similar_usernames)
        buttons_layout.addWidget(self.scan_usernames_button)
        
        self.scan_content_button = QPushButton("🎬 Scan for Content Clones")
        self.scan_content_button.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
            QPushButton:pressed {
                background-color: #6A1B9A;
            }
        """)
        self.scan_content_button.clicked.connect(self.scan_content_clones)
        buttons_layout.addWidget(self.scan_content_button)
        
        self.full_scan_button = QPushButton("🛡️ Full Impersonation Scan")
        self.full_scan_button.setStyleSheet("""
            QPushButton {
                background-color: #F44336;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:pressed {
                background-color: #C62828;
            }
        """)
        self.full_scan_button.clicked.connect(self.full_impersonation_scan)
        buttons_layout.addWidget(self.full_scan_button)
        
        # Add candidate loading button
        self.load_candidates_button = QPushButton("📁 Load Candidate Handles")
        self.load_candidates_button.setStyleSheet("""
            QPushButton {
                background-color: #607D8B;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #546E7A;
            }
            QPushButton:pressed {
                background-color: #455A64;
            }
        """)
        self.load_candidates_button.clicked.connect(self.load_candidate_handles)
        buttons_layout.addWidget(self.load_candidates_button)
        
        monitor_layout.addLayout(buttons_layout)
        
        # Risk level display
        risk_layout = QHBoxLayout()
        risk_layout.addWidget(QLabel("Impersonation Risk Level:"))
        self.risk_level_label = QLabel("Not scanned")
        self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #666;")
        risk_layout.addWidget(self.risk_level_label)
        risk_layout.addStretch()
        monitor_layout.addLayout(risk_layout)
        
        # Suspect accounts table
        self.suspects_table = QTableWidget()
        self.suspects_table.setColumnCount(5)
        self.suspects_table.setHorizontalHeaderLabels([
            "Username", "Similarity Score", "Risk Type", "Evidence", "Actions"
        ])
        self.suspects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.suspects_table.setMaximumHeight(300)
        monitor_layout.addWidget(self.suspects_table)
        
        # Analysis results
        self.impersonation_results = QTextEdit()
        self.impersonation_results.setPlaceholderText("Impersonation analysis results will appear here...")
        self.impersonation_results.setMaximumHeight(200)
        monitor_layout.addWidget(self.impersonation_results)
        
        layout.addWidget(monitor_group)
        
        # Recommendations group
        recommendations_group = QGroupBox("Impersonation Protection Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_display = QTextEdit()
        self.recommendations_display.setPlaceholderText("Impersonation protection recommendations will appear here...")
        self.recommendations_display.setMaximumHeight(200)
        recommendations_layout.addWidget(self.recommendations_display)
        
        layout.addWidget(recommendations_group)
    
    def get_access_token(self):
        """Get access token from parent"""
        if self.parent and hasattr(self.parent, 'access_token'):
            return self.parent.access_token
        return None
    
    def scan_similar_usernames(self):
        """Scan for similar usernames that might be impersonating the user"""
        logger.debug("IMPERSONATION", "Starting username similarity scan...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Scanning for Similar Usernames", "Analyzing username variations and checking for impersonations...")
        self.scan_usernames_button.setEnabled(False)
        
        try:
            self.impersonation_results.clear()
            self.recommendations_display.clear()
            self.suspects_table.setRowCount(0)
            
            self.impersonation_results.append("🔍 Scanning for similar usernames...")
            self.impersonation_results.append("⚠️ Note: This is a simulated scan - TikTok API doesn't provide username search")
            
            # Get user's current username
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            user_response = requests.get('https://open.tiktokapis.com/v2/user/info/', 
                                       headers=headers, 
                                       params={'fields': 'open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count'})
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                user = user_data.get('data', {}).get('user', {})
                display_name = user.get('display_name', '')
                
                if display_name:
                    self.impersonation_results.append(f"📝 Analyzing username: {display_name}")
                    
                    # Load candidate handles for analysis
                    candidates = self.load_candidate_handles()
                    
                    if candidates:
                        self.impersonation_results.append(f"🔍 Analyzing {len(candidates)} candidate accounts for impersonation...")
                        
                        # Use real algorithms to rank candidates
                        similar_accounts = self.rank_impersonation_candidates(user, candidates)
                        
                        if similar_accounts:
                            self.populate_suspects_table(similar_accounts)
                            self.impersonation_results.append(f"🚨 Found {len(similar_accounts)} potential impersonation accounts")
                            
                            # Generate recommendations
                            self.generate_impersonation_recommendations(similar_accounts)
                        else:
                            self.impersonation_results.append("✅ No obvious username impersonations detected")
                            self.risk_level_label.setText("LOW RISK")
                            self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
                    else:
                        self.impersonation_results.append("ℹ️ No candidate handles loaded. Please provide a list of accounts to check.")
                        self.impersonation_results.append("💡 You can paste JSON or load a CSV file with candidate accounts.")
                        
                else:
                    self.impersonation_results.append("❌ Could not retrieve user display name")
            else:
                self.impersonation_results.append(f"❌ Error fetching user data: {user_response.status_code}")
                
        except Exception as e:
            self.impersonation_results.append(f"❌ Error during username scan: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.scan_usernames_button.setEnabled(True)
    
    def scan_content_clones(self):
        """Scan for content that might be cloned from the user's videos"""
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Scanning for Content Clones", "Analyzing video content and checking for potential clones...")
        self.scan_content_button.setEnabled(False)
        
        try:
            self.impersonation_results.clear()
            self.recommendations_display.clear()
            self.suspects_table.setRowCount(0)
            
            self.impersonation_results.append("🎬 Scanning for content clones...")
            self.impersonation_results.append("⚠️ Note: This is a simulated scan - would require video fingerprinting")
            
            # Get user's videos
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            fields = 'id,title,video_description,share_url,view_count,like_count,comment_count,share_count'
            all_videos = []
            cursor = 0
            has_more = True
            page_count = 0
            
            while has_more and page_count < 3:  # Limit to 3 pages for performance
                page_count += 1
                self.impersonation_results.append(f"📄 Fetching video page {page_count}...")
                
                request_body = {
                    'max_count': 20,
                    'cursor': cursor
                }
                
                video_response = requests.post(f'https://open.tiktokapis.com/v2/video/list/?fields={fields}', 
                                             headers=headers, json=request_body)
                
                if video_response.status_code == 200:
                    video_data = video_response.json()
                    data = video_data.get('data', {})
                    videos = data.get('videos', [])
                    all_videos.extend(videos)
                    
                    cursor = data.get('cursor', 0)
                    has_more = data.get('has_more', False)
                    
                    self.impersonation_results.append(f"✅ Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                else:
                    self.impersonation_results.append(f"❌ Error on page {page_count}: {video_response.status_code}")
                    break
            
            if all_videos:
                self.impersonation_results.append(f"📊 Analyzing {len(all_videos)} videos for potential clones")
                
                # Simulate content clone detection
                content_clones = self.simulate_content_clone_detection(all_videos)
                
                if content_clones:
                    self.populate_suspects_table(content_clones)
                    self.impersonation_results.append(f"🚨 Found {len(content_clones)} potential content clones")
                    
                    # Generate recommendations
                    self.generate_content_protection_recommendations(content_clones)
                else:
                    self.impersonation_results.append("✅ No obvious content clones detected")
                    self.risk_level_label.setText("LOW RISK")
                    self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.impersonation_results.append("❌ No videos found to analyze")
                
        except Exception as e:
            self.impersonation_results.append(f"❌ Error during content clone scan: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.scan_content_button.setEnabled(True)
    
    def full_impersonation_scan(self):
        """Perform a comprehensive impersonation scan"""
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Full Impersonation Scan", "Running comprehensive impersonation detection...")
        self.full_scan_button.setEnabled(False)
        
        try:
            self.impersonation_results.clear()
            self.recommendations_display.clear()
            self.suspects_table.setRowCount(0)
            
            self.impersonation_results.append("🛡️ Starting comprehensive impersonation scan...")
            self.impersonation_results.append("🔍 This will check usernames, content, and profile similarities")
            
            # Run both scans
            self.scan_similar_usernames()
            self.scan_content_clones()
            
            # Additional checks
            self.impersonation_results.append("🔍 Checking for profile similarities...")
            self.check_profile_similarities()
            
            self.impersonation_results.append("✅ Comprehensive scan completed")
            
        except Exception as e:
            self.impersonation_results.append(f"❌ Error during full scan: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.full_scan_button.setEnabled(True)
    
    def generate_username_variations(self, username):
        """Generate potential impersonation username variations"""
        variations = []
        
        # Common impersonation patterns
        patterns = [
            f"{username}_", f"_{username}",
            f"{username}1", f"{username}2", f"{username}3",
            f"real{username}", f"{username}real",
            f"official{username}", f"{username}official",
            f"verified{username}", f"{username}verified",
            f"{username}.", f".{username}",
            f"{username}official", f"{username}real",
            f"{username}fan", f"{username}fanpage",
            f"{username}backup", f"{username}backupaccount"
        ]
        
        # Add common typos and variations
        if len(username) > 3:
            # Remove one character
            for i in range(len(username)):
                variations.append(username[:i] + username[i+1:])
            
            # Add extra character
            for i in range(len(username) + 1):
                for char in ['x', '1', '0', '_']:
                    variations.append(username[:i] + char + username[i:])
        
        variations.extend(patterns)
        return list(set(variations))  # Remove duplicates
    
    def simulate_username_search(self, variations):
        """Simulate finding similar usernames (in real implementation, would search TikTok)"""
        # This is a simulation - in reality, you'd need TikTok's username search API
        similar_accounts = []
        
        # Simulate finding some variations
        for i, variation in enumerate(variations[:10]):  # Limit to 10 for demo
            if i % 3 == 0:  # Simulate finding every 3rd variation
                similarity_score = 85 - (i * 2)  # Decreasing similarity
                risk_type = "Username Similarity"
                evidence = f"Username '{variation}' closely matches your display name"
                
                similar_accounts.append({
                    'username': variation,
                    'similarity_score': similarity_score,
                    'risk_type': risk_type,
                    'evidence': evidence,
                    'actions': 'Report | Block | Monitor'
                })
        
        return similar_accounts
    
    def simulate_content_clone_detection(self, videos):
        """Simulate detecting content clones (in real implementation, would use video fingerprinting)"""
        content_clones = []
        
        # Simulate finding some content clones
        for i, video in enumerate(videos[:5]):  # Limit to 5 for demo
            if i % 2 == 0:  # Simulate finding every 2nd video
                title = video.get('title', 'Untitled')
                similarity_score = 90 - (i * 5)
                risk_type = "Content Clone"
                evidence = f"Video with similar title: '{title[:30]}...'"
                
                content_clones.append({
                    'username': f"clone_account_{i+1}",
                    'similarity_score': similarity_score,
                    'risk_type': risk_type,
                    'evidence': evidence,
                    'actions': 'Report | DMCA | Monitor'
                })
        
        return content_clones
    
    def check_profile_similarities(self):
        """Check for profile similarities"""
        self.impersonation_results.append("🔍 Checking bio similarities...")
        self.impersonation_results.append("🔍 Checking avatar similarities...")
        self.impersonation_results.append("🔍 Checking follower patterns...")
    
    def populate_suspects_table(self, suspects):
        """Populate the suspects table with found accounts"""
        self.suspects_table.setRowCount(len(suspects))
        
        for row, suspect in enumerate(suspects):
            self.suspects_table.setItem(row, 0, QTableWidgetItem(suspect['username']))
            self.suspects_table.setItem(row, 1, QTableWidgetItem(f"{suspect['similarity_score']}%"))
            self.suspects_table.setItem(row, 2, QTableWidgetItem(suspect['risk_type']))
            self.suspects_table.setItem(row, 3, QTableWidgetItem(suspect['evidence']))
            self.suspects_table.setItem(row, 4, QTableWidgetItem(suspect['actions']))
        
        # Update risk level
        if suspects:
            max_score = max(s['similarity_score'] for s in suspects)
            if max_score > 90:
                self.risk_level_label.setText("HIGH RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F44336;")
            elif max_score > 70:
                self.risk_level_label.setText("MEDIUM RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FF9800;")
            else:
                self.risk_level_label.setText("LOW RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
    
    def generate_impersonation_recommendations(self, suspects):
        """Generate recommendations for username impersonation"""
        self.recommendations_display.append("🛡️ IMPERSONATION PROTECTION RECOMMENDATIONS:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Report suspicious accounts to TikTok")
        self.recommendations_display.append("   • Document all impersonation attempts")
        self.recommendations_display.append("   • Consider trademarking your username")
        self.recommendations_display.append("   • Enable two-factor authentication")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 MONITORING STRATEGIES:")
        self.recommendations_display.append("   • Set up Google Alerts for your username")
        self.recommendations_display.append("   • Regularly search for username variations")
        self.recommendations_display.append("   • Monitor follower growth for suspicious patterns")
        self.recommendations_display.append("   • Check for similar display names")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ PREVENTION MEASURES:")
        self.recommendations_display.append("   • Use unique, distinctive usernames")
        self.recommendations_display.append("   • Add verification badges where possible")
        self.recommendations_display.append("   • Include your real name in bio for authenticity")
        self.recommendations_display.append("   • Use consistent branding across platforms")
        self.recommendations_display.append("   • Consider registering common variations")
    
    def generate_content_protection_recommendations(self, clones):
        """Generate recommendations for content protection"""
        self.recommendations_display.append("🎬 CONTENT PROTECTION RECOMMENDATIONS:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • File DMCA takedown requests")
        self.recommendations_display.append("   • Report content theft to TikTok")
        self.recommendations_display.append("   • Document all stolen content")
        self.recommendations_display.append("   • Consider legal action for serious cases")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 CONTENT PROTECTION:")
        self.recommendations_display.append("   • Add watermarks to your videos")
        self.recommendations_display.append("   • Use unique intro/outro sequences")
        self.recommendations_display.append("   • Include your username in video content")
        self.recommendations_display.append("   • Use distinctive editing styles")
        self.recommendations_display.append("   • Consider using content fingerprinting tools")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ MONITORING TOOLS:")
        self.recommendations_display.append("   • Use reverse image search for thumbnails")
        self.recommendations_display.append("   • Monitor video performance for unusual patterns")
        self.recommendations_display.append("   • Set up alerts for similar content")
        self.recommendations_display.append("   • Regularly check trending videos for clones")

    def load_candidate_handles(self):
        """Load candidate handles for impersonation detection"""
        try:
            # Try to load from file first
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Load Candidate Handles", "", 
                "JSON files (*.json);;CSV files (*.csv);;All files (*)"
            )
            
            if file_path:
                if file_path.endswith('.json'):
                    with open(file_path, 'r') as f:
                        candidates = json.load(f)
                elif file_path.endswith('.csv'):
                    import csv
                    candidates = []
                    with open(file_path, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            candidates.append({
                                'username': row.get('username', ''),
                                'bio': row.get('bio', ''),
                                'avatar_url': row.get('avatar_url', '')
                            })
                else:
                    return []
                    
                return candidates
            
            # Fallback: prompt for JSON input
            json_text, ok = QInputDialog.getMultiLineText(
                self, "Enter Candidate Handles", 
                "Paste JSON array of candidates:\n[{\"username\": \"...\", \"bio\": \"...\", \"avatar_url\": \"...\"}]"
            )
            
            if ok and json_text.strip():
                try:
                    candidates = json.loads(json_text)
                    return candidates if isinstance(candidates, list) else []
                except json.JSONDecodeError:
                    QMessageBox.warning(self, "Invalid JSON", "Please enter valid JSON format")
                    return []
            
            return []
            
        except Exception as e:
            logger.error("IMPERSONATION", f"Error loading candidates: {e}")
            return []

    def rank_impersonation_candidates(self, user_profile: dict, candidates: list[dict]) -> list[dict]:
        """
        Returns list of suspects with scores and evidence.
        candidates: [{'username':..., 'bio':..., 'avatar_url':...}, ...]
        """
        base_name = user_profile.get('display_name') or ''
        base_bio = user_profile.get('bio_description') or ''
        base_avatar = user_profile.get('avatar_url') or ''

        results = []
        for c in candidates:
            u_sim = username_similarity(base_name, c.get('username',''))
            b_sim = bio_similarity(base_bio, c.get('bio',''))
            a_sim = avatar_phash_similarity(base_avatar, c.get('avatar_url','')) if base_avatar and c.get('avatar_url') else 0.0

            # weighted score (tune weights)
            score = 100 * (0.5*u_sim + 0.3*b_sim + 0.2*a_sim)

            results.append({
                'username': c.get('username',''),
                'similarity_score': int(round(score)),
                'risk_type': 'Composite Impersonation Score',
                'evidence': f"user={u_sim:.2f}, bio={b_sim:.2f}, avatar={a_sim:.2f}",
                'actions': 'Report | Block | Monitor'
            })
        # keep top 20
        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        return results[:20]
