"""
TikTok Stalkerware Warning Tool Tab Component
Detects obsessive monitoring behavior and potential stalking patterns
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QSlider, QProgressBar
)
from PySide6.QtCore import Qt
import requests
import json
import re
import statistics
from datetime import datetime, timedelta
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingSpinner


class StalkerwareTab(QWidget):
    """TikTok Stalkerware Warning Tool tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
        # Initialize loading spinner
        self.loading_spinner = LoadingSpinner(self)
    
    def setup_ui(self):
        """Setup the stalkerware detection UI"""
        layout = QVBoxLayout(self)
        
        # Stalkerware Detection group
        stalkerware_group = QGroupBox("TikTok Stalkerware Warning Tool")
        stalkerware_layout = QVBoxLayout(stalkerware_group)
        
        # Analysis buttons
        buttons_layout = QHBoxLayout()
        
        self.detect_stalkers_button = QPushButton("🕵️ Detect Stalkerware")
        self.detect_stalkers_button.setStyleSheet("""
            QPushButton {
                background-color: #E91E63;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #C2185B;
            }
            QPushButton:pressed {
                background-color: #AD1457;
            }
        """)
        self.detect_stalkers_button.clicked.connect(self.detect_stalkerware)
        buttons_layout.addWidget(self.detect_stalkers_button)
        
        self.analyze_patterns_button = QPushButton("📊 Analyze Patterns")
        self.analyze_patterns_button.setStyleSheet("""
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
        self.analyze_patterns_button.clicked.connect(self.analyze_interaction_patterns)
        buttons_layout.addWidget(self.analyze_patterns_button)
        
        self.full_scan_button = QPushButton("🛡️ Full Stalkerware Scan")
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
        self.full_scan_button.clicked.connect(self.full_stalkerware_scan)
        buttons_layout.addWidget(self.full_scan_button)
        
        stalkerware_layout.addLayout(buttons_layout)
        
        # Sensitivity slider
        sensitivity_layout = QHBoxLayout()
        sensitivity_layout.addWidget(QLabel("Detection Sensitivity:"))
        self.sensitivity_slider = QSlider()
        self.sensitivity_slider.setOrientation(Qt.Horizontal)
        self.sensitivity_slider.setRange(1, 10)
        self.sensitivity_slider.setValue(5)
        self.sensitivity_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                border: 1px solid #999999;
                height: 8px;
                background: #f0f0f0;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #E91E63;
                border: 1px solid #C2185B;
                width: 18px;
                margin: -2px 0;
                border-radius: 9px;
            }
        """)
        sensitivity_layout.addWidget(self.sensitivity_slider)
        self.sensitivity_label = QLabel("5")
        self.sensitivity_slider.valueChanged.connect(lambda v: self.sensitivity_label.setText(str(v)))
        sensitivity_layout.addWidget(self.sensitivity_label)
        sensitivity_layout.addStretch()
        stalkerware_layout.addLayout(sensitivity_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        stalkerware_layout.addWidget(self.progress_bar)
        
        # Risk level display
        risk_layout = QHBoxLayout()
        risk_layout.addWidget(QLabel("Stalkerware Risk Level:"))
        self.risk_level_label = QLabel("Not analyzed")
        self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #666;")
        risk_layout.addWidget(self.risk_level_label)
        risk_layout.addStretch()
        stalkerware_layout.addLayout(risk_layout)
        
        layout.addWidget(stalkerware_group)
        
        # Results table
        results_group = QGroupBox("Detected Stalkerware Patterns")
        results_layout = QVBoxLayout(results_group)
        
        self.stalkerware_table = QTableWidget()
        self.stalkerware_table.setColumnCount(5)
        self.stalkerware_table.setHorizontalHeaderLabels([
            "Pattern Type", "Severity", "Evidence", "Confidence", "Actions"
        ])
        self.stalkerware_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stalkerware_table.setMaximumHeight(200)
        results_layout.addWidget(self.stalkerware_table)
        
        # Analysis results
        self.stalkerware_results = QTextEdit()
        self.stalkerware_results.setPlaceholderText("Stalkerware analysis results will appear here...")
        self.stalkerware_results.setMaximumHeight(150)
        results_layout.addWidget(self.stalkerware_results)
        
        layout.addWidget(results_group)
        
        # Recommendations group
        recommendations_group = QGroupBox("Stalkerware Protection Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_display = QTextEdit()
        self.recommendations_display.setPlaceholderText("Stalkerware protection recommendations will appear here...")
        self.recommendations_display.setMaximumHeight(200)
        recommendations_layout.addWidget(self.recommendations_display)
        
        layout.addWidget(recommendations_group)
    
    def get_access_token(self):
        """Get access token from main application"""
        if self.parent and hasattr(self.parent, 'parent') and self.parent.parent:
            return self.parent.parent.access_token
        return None
    
    def detect_stalkerware(self):
        """Detect potential stalkerware behavior patterns"""
        logger.debug("STALKERWARE", "Starting stalkerware detection...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Detecting Stalkerware", "Analyzing follower interaction patterns...")
        self.detect_stalkers_button.setEnabled(False)
        
        try:
            self.stalkerware_results.clear()
            self.recommendations_display.clear()
            self.stalkerware_table.setRowCount(0)
            
            self.stalkerware_results.append("🕵️ Starting stalkerware detection...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Get user's videos and analyze interaction patterns
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            fields = 'id,title,video_description,view_count,like_count,comment_count,share_count'
            all_videos = []
            cursor = 0
            has_more = True
            page_count = 0
            
            while has_more and page_count < 3:  # Limit to 3 pages for performance
                page_count += 1
                self.progress_bar.setValue(page_count * 20)
                self.stalkerware_results.append(f"📄 Fetching video page {page_count}...")
                
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
                    
                    self.stalkerware_results.append(f"✅ Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                else:
                    self.stalkerware_results.append(f"❌ Error on page {page_count}: {video_response.status_code}")
                    break
            
            if all_videos:
                self.stalkerware_results.append(f"📊 Analyzing {len(all_videos)} videos for stalkerware patterns...")
                self.progress_bar.setValue(60)
                
                # Analyze for stalkerware patterns
                stalkerware_patterns = self.analyze_stalkerware_patterns(all_videos)
                
                if stalkerware_patterns:
                    self.populate_stalkerware_table(stalkerware_patterns)
                    self.stalkerware_results.append(f"🚨 Found {len(stalkerware_patterns)} potential stalkerware patterns")
                    
                    # Calculate overall risk score
                    avg_confidence = sum(p['confidence'] for p in stalkerware_patterns) / len(stalkerware_patterns)
                    self.risk_level_label.setText(f"{avg_confidence:.1f}/100")
                    self.set_risk_level_style(avg_confidence)
                    
                    # Generate recommendations
                    self.generate_stalkerware_recommendations(stalkerware_patterns)
                else:
                    self.stalkerware_results.append("✅ No obvious stalkerware patterns detected")
                    self.risk_level_label.setText("0.0/100")
                    self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.stalkerware_results.append("❌ No videos found to analyze")
            
            self.progress_bar.setValue(100)
            self.progress_bar.setVisible(False)
                
        except Exception as e:
            self.stalkerware_results.append(f"❌ Error during stalkerware detection: {e}")
            self.progress_bar.setVisible(False)
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.detect_stalkers_button.setEnabled(True)
    
    def analyze_interaction_patterns(self):
        """Analyze interaction patterns for obsessive behavior"""
        logger.debug("STALKERWARE", "Starting interaction pattern analysis...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Analyzing Interaction Patterns", "Examining engagement timing and frequency...")
        self.analyze_patterns_button.setEnabled(False)
        
        try:
            self.stalkerware_results.clear()
            self.recommendations_display.clear()
            self.stalkerware_table.setRowCount(0)
            
            self.stalkerware_results.append("📊 Starting interaction pattern analysis...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Get user's videos
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            fields = 'id,title,video_description,view_count,like_count,comment_count,share_count'
            all_videos = []
            cursor = 0
            has_more = True
            page_count = 0
            
            while has_more and page_count < 3:
                page_count += 1
                self.progress_bar.setValue(page_count * 25)
                self.stalkerware_results.append(f"📄 Fetching video page {page_count}...")
                
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
                    
                    self.stalkerware_results.append(f"✅ Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                else:
                    self.stalkerware_results.append(f"❌ Error on page {page_count}: {video_response.status_code}")
                    break
            
            if all_videos:
                self.stalkerware_results.append(f"📊 Analyzing interaction patterns across {len(all_videos)} videos...")
                self.progress_bar.setValue(60)
                
                # Analyze interaction patterns
                interaction_patterns = self.analyze_obsessive_patterns(all_videos)
                
                if interaction_patterns:
                    self.populate_stalkerware_table(interaction_patterns)
                    self.stalkerware_results.append(f"🚨 Found {len(interaction_patterns)} obsessive interaction patterns")
                    
                    # Calculate overall risk score
                    avg_confidence = sum(p['confidence'] for p in interaction_patterns) / len(interaction_patterns)
                    self.risk_level_label.setText(f"{avg_confidence:.1f}/100")
                    self.set_risk_level_style(avg_confidence)
                    
                    # Generate recommendations
                    self.generate_interaction_recommendations(interaction_patterns)
                else:
                    self.stalkerware_results.append("✅ No obsessive interaction patterns detected")
                    self.risk_level_label.setText("0.0/100")
                    self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.stalkerware_results.append("❌ No videos found to analyze")
            
            self.progress_bar.setValue(100)
            self.progress_bar.setVisible(False)
                
        except Exception as e:
            self.stalkerware_results.append(f"❌ Error during interaction analysis: {e}")
            self.progress_bar.setVisible(False)
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.analyze_patterns_button.setEnabled(True)
    
    def full_stalkerware_scan(self):
        """Perform a comprehensive stalkerware scan"""
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Full Stalkerware Scan", "Running comprehensive stalkerware detection...")
        self.full_scan_button.setEnabled(False)
        
        try:
            self.stalkerware_results.clear()
            self.recommendations_display.clear()
            self.stalkerware_table.setRowCount(0)
            
            self.stalkerware_results.append("🛡️ Starting comprehensive stalkerware scan...")
            self.stalkerware_results.append("🔍 This will check for stalkerware patterns and obsessive behavior")
            
            # Run both scans
            self.detect_stalkerware()
            self.analyze_interaction_patterns()
            
            self.stalkerware_results.append("✅ Comprehensive stalkerware scan completed")
            
        except Exception as e:
            self.stalkerware_results.append(f"❌ Error during full scan: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.full_scan_button.setEnabled(True)
    
    def analyze_stalkerware_patterns(self, videos):
        """Analyze videos for potential stalkerware behavior patterns"""
        patterns = []
        sensitivity = self.sensitivity_slider.value()
        
        # Thresholds scale with sensitivity (higher = more strict)
        engagement_thresh = max(0.8, 0.95 - (sensitivity * 0.015))
        frequency_thresh = max(0.7, 0.9 - (sensitivity * 0.02))
        timing_thresh = max(0.6, 0.85 - (sensitivity * 0.025))
        
        for video in videos:
            view_count = video.get('view_count', 0)
            like_count = video.get('like_count', 0)
            comment_count = video.get('comment_count', 0)
            share_count = video.get('share_count', 0)
            
            if view_count == 0:
                continue
            
            # Calculate engagement ratios
            like_ratio = like_count / view_count if view_count > 0 else 0
            comment_ratio = comment_count / view_count if view_count > 0 else 0
            share_ratio = share_count / view_count if view_count > 0 else 0
            
            # Stalkerware detection patterns
            stalker_indicators = []
            confidence = 0
            
            # 1. Unusually high engagement ratios (potential bot farms or obsessive followers)
            if like_ratio > engagement_thresh:
                stalker_indicators.append(f"Excessive like ratio: {like_ratio:.2%}")
                confidence += 25
            
            if comment_ratio > engagement_thresh * 0.5:
                stalker_indicators.append(f"Excessive comment ratio: {comment_ratio:.2%}")
                confidence += 20
            
            # 2. Perfect engagement timing (suspicious)
            if like_ratio > 0.9 and comment_ratio > 0.1:
                stalker_indicators.append("Perfect engagement ratios (suspicious)")
                confidence += 30
            
            # 3. Low view count but high engagement (targeted stalking)
            if view_count < 500 and (like_ratio > 0.5 or comment_ratio > 0.1):
                stalker_indicators.append("Low views but high engagement (targeted stalking)")
                confidence += 35
            
            # 4. Suspicious share ratios (content spreading)
            if share_ratio > 0.3:
                stalker_indicators.append(f"Excessive share ratio: {share_ratio:.2%}")
                confidence += 15
            
            # Apply sensitivity multiplier
            confidence = min(100, confidence * (sensitivity / 5))
            
            if confidence > 30:  # Only report significant patterns
                patterns.append({
                    'pattern_type': 'Stalkerware Behavior',
                    'severity': 'HIGH' if confidence > 70 else 'MEDIUM' if confidence > 50 else 'LOW',
                    'evidence': '; '.join(stalker_indicators),
                    'confidence': confidence,
                    'actions': 'Block | Report | Monitor'
                })
        
        return patterns
    
    def analyze_obsessive_patterns(self, videos):
        """Analyze for obsessive interaction patterns"""
        patterns = []
        sensitivity = self.sensitivity_slider.value()
        
        # Analyze engagement frequency and timing patterns
        engagement_data = []
        for video in videos:
            view_count = video.get('view_count', 0)
            like_count = video.get('like_count', 0)
            comment_count = video.get('comment_count', 0)
            
            if view_count > 0:
                engagement_data.append({
                    'video_id': video.get('id', 'Unknown'),
                    'engagement_rate': (like_count + comment_count) / view_count,
                    'like_ratio': like_count / view_count,
                    'comment_ratio': comment_count / view_count
                })
        
        if len(engagement_data) > 1:
            # Calculate statistical patterns
            engagement_rates = [d['engagement_rate'] for d in engagement_data]
            like_ratios = [d['like_ratio'] for d in engagement_data]
            comment_ratios = [d['comment_ratio'] for d in engagement_data]
            
            # Detect unusual patterns
            mean_engagement = statistics.mean(engagement_rates)
            std_engagement = statistics.stdev(engagement_rates) if len(engagement_rates) > 1 else 0
            
            for data in engagement_data:
                video_id = data['video_id']
                engagement_rate = data['engagement_rate']
                like_ratio = data['like_ratio']
                comment_ratio = data['comment_ratio']
                
                indicators = []
                confidence = 0
                
                # Z-score analysis for engagement patterns
                if std_engagement > 0:
                    z_score = abs((engagement_rate - mean_engagement) / std_engagement)
                    if z_score > 2.5:
                        indicators.append(f"Engagement z-score: {z_score:.2f}")
                        confidence += min(30, z_score * 10)
                
                # Excessive engagement ratios
                if like_ratio > 0.8:
                    indicators.append(f"Excessive like ratio: {like_ratio:.2%}")
                    confidence += 20
                
                if comment_ratio > 0.15:
                    indicators.append(f"Excessive comment ratio: {comment_ratio:.2%}")
                    confidence += 25
                
                # Apply sensitivity
                confidence = min(100, confidence * (sensitivity / 5))
                
                if confidence > 25 and indicators:
                    patterns.append({
                        'pattern_type': 'Obsessive Interaction',
                        'severity': 'HIGH' if confidence > 70 else 'MEDIUM' if confidence > 50 else 'LOW',
                        'evidence': '; '.join(indicators),
                        'confidence': confidence,
                        'actions': 'Block | Report | Monitor'
                    })
        
        return patterns
    
    def populate_stalkerware_table(self, patterns):
        """Populate the stalkerware table with detected patterns"""
        self.stalkerware_table.setRowCount(len(patterns))
        
        for row, pattern in enumerate(patterns):
            self.stalkerware_table.setItem(row, 0, QTableWidgetItem(pattern['pattern_type']))
            self.stalkerware_table.setItem(row, 1, QTableWidgetItem(pattern['severity']))
            self.stalkerware_table.setItem(row, 2, QTableWidgetItem(pattern['evidence']))
            self.stalkerware_table.setItem(row, 3, QTableWidgetItem(f"{pattern['confidence']:.1f}%"))
            self.stalkerware_table.setItem(row, 4, QTableWidgetItem(pattern['actions']))
        
        # Update risk level
        if patterns:
            max_confidence = max(p['confidence'] for p in patterns)
            if max_confidence > 80:
                self.risk_level_label.setText("HIGH RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F44336;")
            elif max_confidence > 60:
                self.risk_level_label.setText("MEDIUM RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FF9800;")
            else:
                self.risk_level_label.setText("LOW RISK")
                self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
    
    def set_risk_level_style(self, confidence):
        """Set the risk level label style based on confidence score"""
        if confidence > 80:
            self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F44336;")
        elif confidence > 60:
            self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FF9800;")
        elif confidence > 30:
            self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FFC107;")
        else:
            self.risk_level_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
    
    def generate_stalkerware_recommendations(self, patterns):
        """Generate recommendations for stalkerware protection"""
        self.recommendations_display.append("🛡️ STALKERWARE PROTECTION RECOMMENDATIONS:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Block suspicious accounts immediately")
        self.recommendations_display.append("   • Report stalking behavior to TikTok")
        self.recommendations_display.append("   • Document all suspicious activity")
        self.recommendations_display.append("   • Consider legal action for serious cases")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 MONITORING STRATEGIES:")
        self.recommendations_display.append("   • Monitor follower growth for unusual patterns")
        self.recommendations_display.append("   • Track engagement timing and frequency")
        self.recommendations_display.append("   • Watch for obsessive comment patterns")
        self.recommendations_display.append("   • Check for coordinated bot activity")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ PREVENTION MEASURES:")
        self.recommendations_display.append("   • Enable two-factor authentication")
        self.recommendations_display.append("   • Use strong, unique passwords")
        self.recommendations_display.append("   • Limit personal information in content")
        self.recommendations_display.append("   • Consider private account settings")
        self.recommendations_display.append("   • Regularly review follower list")
        self.recommendations_display.append("   • Use content watermarks")
        self.recommendations_display.append("")
        self.recommendations_display.append("📱 DIGITAL SAFETY:")
        self.recommendations_display.append("   • Enable location privacy settings")
        self.recommendations_display.append("   • Avoid sharing real-time location")
        self.recommendations_display.append("   • Use VPN for additional privacy")
        self.recommendations_display.append("   • Consider professional security consultation")
    
    def generate_interaction_recommendations(self, patterns):
        """Generate recommendations for obsessive interaction protection"""
        self.recommendations_display.append("📊 OBSESSIVE INTERACTION PROTECTION:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Block accounts with obsessive behavior")
        self.recommendations_display.append("   • Report harassment to TikTok")
        self.recommendations_display.append("   • Document interaction patterns")
        self.recommendations_display.append("   • Consider temporary account deactivation")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 BEHAVIORAL ANALYSIS:")
        self.recommendations_display.append("   • Monitor engagement timing patterns")
        self.recommendations_display.append("   • Track comment frequency and content")
        self.recommendations_display.append("   • Watch for coordinated activity")
        self.recommendations_display.append("   • Analyze follower growth anomalies")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ PROTECTION STRATEGIES:")
        self.recommendations_display.append("   • Use comment filtering")
        self.recommendations_display.append("   • Enable follower approval")
        self.recommendations_display.append("   • Limit content visibility")
        self.recommendations_display.append("   • Use content scheduling to avoid patterns")
        self.recommendations_display.append("   • Consider professional moderation")
        self.recommendations_display.append("")
        self.recommendations_display.append("🧠 MENTAL HEALTH:")
        self.recommendations_display.append("   • Take breaks from social media")
        self.recommendations_display.append("   • Seek support if feeling threatened")
        self.recommendations_display.append("   • Consider professional counseling")
        self.recommendations_display.append("   • Remember: your safety comes first")
