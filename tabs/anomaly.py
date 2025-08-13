"""
Engagement Anomaly Detector Tab Component
Detects bots, fake followers, or strange traffic on videos
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QSlider, QSizePolicy, QApplication
)
from PySide6.QtCore import Qt
import requests
import json
import re
import math
import statistics
from datetime import datetime, timedelta
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingSpinner


class AnomalyTab(QWidget):
    """Engagement Anomaly Detector tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
        # Initialize loading spinner
        self.loading_spinner = LoadingSpinner(self)
    
    def setup_ui(self):
        """Setup the anomaly detector UI"""
        layout = QVBoxLayout(self)
        
        # Anomaly Detection group
        anomaly_group = QGroupBox("Engagement Anomaly Detector")
        anomaly_layout = QVBoxLayout(anomaly_group)
        
        # Analysis buttons
        buttons_layout = QHBoxLayout()
        
        self.detect_bots_button = QPushButton("🤖 Bot Detection")
        self.detect_bots_button.setStyleSheet("""
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
        self.detect_bots_button.clicked.connect(self.detect_bots)
        buttons_layout.addWidget(self.detect_bots_button)
        
        self.engagement_analysis_button = QPushButton("📊 Engagement Analysis")
        self.engagement_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """)
        self.engagement_analysis_button.clicked.connect(self.analyze_engagement_patterns)
        buttons_layout.addWidget(self.engagement_analysis_button)
        
        self.traffic_analysis_button = QPushButton("🚦 Traffic Analysis")
        self.traffic_analysis_button.setStyleSheet("""
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
        self.traffic_analysis_button.clicked.connect(self.analyze_traffic_patterns)
        buttons_layout.addWidget(self.traffic_analysis_button)
        
        self.full_anomaly_scan_button = QPushButton("🔍 Full Anomaly Scan")
        self.full_anomaly_scan_button.setStyleSheet("""
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
        self.full_anomaly_scan_button.clicked.connect(self.full_anomaly_scan)
        buttons_layout.addWidget(self.full_anomaly_scan_button)
        
        anomaly_layout.addLayout(buttons_layout)
        
        # Sensitivity slider
        sensitivity_layout = QHBoxLayout()
        sensitivity_layout.addWidget(QLabel("Detection Sensitivity:"))
        self.sensitivity_slider = QSlider()
        self.sensitivity_slider.setOrientation(Qt.Horizontal)
        self.sensitivity_slider.setMinimum(1)
        self.sensitivity_slider.setMaximum(10)
        self.sensitivity_slider.setValue(5)
        self.sensitivity_slider.setTickPosition(QSlider.TicksBelow)
        self.sensitivity_slider.setTickInterval(1)
        sensitivity_layout.addWidget(self.sensitivity_slider)
        self.sensitivity_label = QLabel("5 (Medium)")
        sensitivity_layout.addWidget(self.sensitivity_label)
        self.sensitivity_slider.valueChanged.connect(self.update_sensitivity_label)
        anomaly_layout.addLayout(sensitivity_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(8)  # thin
        self.progress_bar.setStyleSheet("QProgressBar { border: 0; } QProgressBar::chunk { margin: 0; }")
        anomaly_layout.addWidget(self.progress_bar)
        
        # Anomaly score display
        score_layout = QHBoxLayout()
        score_layout.addWidget(QLabel("Anomaly Score:"))
        self.anomaly_score_label = QLabel("Not analyzed")
        self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #666;")
        score_layout.addWidget(self.anomaly_score_label)
        score_layout.addStretch()
        anomaly_layout.addLayout(score_layout)
        
        # Anomalies table
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(5)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Video ID", "Anomaly Type", "Severity", "Evidence", "Confidence"
        ])
        self.anomalies_table.horizontalHeader().setStretchLastSection(True)
        self.anomalies_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.anomalies_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.anomalies_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.anomalies_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)  # Evidence stretches
        self.anomalies_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.anomalies_table.setWordWrap(True)
        self.anomalies_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.anomalies_table.setMinimumHeight(220)
        anomaly_layout.addWidget(self.anomalies_table)
        
        # Analysis results
        self.anomaly_results = QTextEdit()
        self.anomaly_results.setPlaceholderText("Anomaly detection results will appear here...")
        self.anomaly_results.setReadOnly(True)
        self.anomaly_results.setAcceptRichText(False)
        self.anomaly_results.setLineWrapMode(QTextEdit.WidgetWidth)
        self.anomaly_results.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.anomaly_results.setMinimumHeight(160)
        anomaly_layout.addWidget(self.anomaly_results)
        
        layout.addWidget(anomaly_group)
        
        # Recommendations group
        recommendations_group = QGroupBox("Anomaly Response Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_display = QTextEdit()
        self.recommendations_display.setPlaceholderText("Anomaly response recommendations will appear here...")
        self.recommendations_display.setReadOnly(True)
        self.recommendations_display.setAcceptRichText(False)
        self.recommendations_display.setLineWrapMode(QTextEdit.WidgetWidth)
        self.recommendations_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.recommendations_display.setMinimumHeight(160)
        recommendations_layout.addWidget(self.recommendations_display)
        
        layout.addWidget(recommendations_group)
    
    def _lock_ui(self, locked: bool):
        for b in (self.detect_bots_button,
                  self.engagement_analysis_button,
                  self.traffic_analysis_button,
                  self.full_anomaly_scan_button):
            b.setEnabled(not locked)

    def _scan_banner(self, title: str, subtitle: str):
        # single source of truth for "spinner"-like UX
        self.anomaly_results.append(f"\n<b>{title}</b>\n{subtitle}")
        # let the UI breathe for a moment so text paints before heavy work
        QApplication.processEvents()
    
    def update_sensitivity_label(self):
        """Update the sensitivity label when slider changes"""
        value = self.sensitivity_slider.value()
        if value <= 3:
            level = "Low"
        elif value <= 7:
            level = "Medium"
        else:
            level = "High"
        self.sensitivity_label.setText(f"{value} ({level})")
    
    def get_access_token(self):
        """Get access token from parent"""
        if self.parent and hasattr(self.parent, 'access_token'):
            return self.parent.access_token
        return None
    
    def detect_bots(self):
        """Detect bot-like behavior in engagement patterns"""
        logger.debug("ANOMALY", "Starting bot detection analysis...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        self._lock_ui(True)
        self._scan_banner("Detecting Bots", "Analyzing engagement patterns for bot-like behavior...")
        
        try:
            self.anomaly_results.clear()
            self.recommendations_display.clear()
            self.anomalies_table.setRowCount(0)
            
            self.anomaly_results.append("🤖 Starting bot detection analysis...")
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
            
            while has_more and page_count < 10:  # Limit to 3 pages for performance
                page_count += 1
                self.progress_bar.setValue(page_count * 20)
                self.anomaly_results.append(f"📄 Fetching video page {page_count}...")
                
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
                    
                    self.anomaly_results.append(f"✅ Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                else:
                    self.anomaly_results.append(f"❌ Error on page {page_count}: {video_response.status_code}")
                    break
            
            if all_videos:
                self.anomaly_results.append(f"📊 Analyzing {len(all_videos)} videos for bot patterns...")
                self.progress_bar.setValue(60)
                
                # Analyze for bot patterns
                bot_anomalies = self.analyze_bot_patterns(all_videos)
                
                if bot_anomalies:
                    self.populate_anomalies_table(bot_anomalies)
                    self.anomaly_results.append(f"🚨 Found {len(bot_anomalies)} potential bot anomalies")
                    
                    # Calculate overall anomaly score
                    avg_confidence = sum(a['confidence'] for a in bot_anomalies) / len(bot_anomalies)
                    self.anomaly_score_label.setText(f"{avg_confidence:.1f}/100")
                    self.set_anomaly_score_style(avg_confidence)
                    
                    # Generate recommendations
                    self.generate_bot_response_recommendations(bot_anomalies)
                else:
                    self.anomaly_results.append("✅ No obvious bot patterns detected")
                    self.anomaly_score_label.setText("0.0/100")
                    self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.anomaly_results.append("❌ No videos found to analyze")
            
            self.progress_bar.setValue(100)
                
        except Exception as e:
            self.anomaly_results.append(f"❌ Error during bot detection: {e}")
        finally:
            # Re-enable UI
            self._lock_ui(False)
    
    def analyze_engagement_patterns(self):
        """Analyze engagement patterns for anomalies"""
        logger.debug("ANOMALY", "Starting engagement pattern analysis...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        self._lock_ui(True)
        self._scan_banner("Analyzing Engagement Patterns", "Examining engagement ratios and patterns...")
        
        try:
            self.anomaly_results.clear()
            self.recommendations_display.clear()
            self.anomalies_table.setRowCount(0)
            
            self.anomaly_results.append("📊 Starting engagement pattern analysis...")
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
                else:
                    break
            
            if all_videos:
                self.anomaly_results.append(f"📊 Analyzing engagement patterns across {len(all_videos)} videos...")
                self.progress_bar.setValue(60)
                
                # Analyze engagement patterns
                engagement_anomalies = self.analyze_engagement_anomalies(all_videos)
                
                if engagement_anomalies:
                    self.populate_anomalies_table(engagement_anomalies)
                    self.anomaly_results.append(f"🚨 Found {len(engagement_anomalies)} engagement anomalies")
                    
                    # Calculate overall anomaly score
                    avg_confidence = sum(a['confidence'] for a in engagement_anomalies) / len(engagement_anomalies)
                    self.anomaly_score_label.setText(f"{avg_confidence:.1f}/100")
                    self.set_anomaly_score_style(avg_confidence)
                    
                    # Generate recommendations
                    self.generate_engagement_recommendations(engagement_anomalies)
                else:
                    self.anomaly_results.append("✅ No engagement anomalies detected")
                    self.anomaly_score_label.setText("0.0/100")
                    self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.anomaly_results.append("❌ No videos found to analyze")
            
            self.progress_bar.setValue(100)
                
        except Exception as e:
            self.anomaly_results.append(f"❌ Error during engagement analysis: {e}")
        finally:
            # Re-enable UI
            self._lock_ui(False)
    
    def analyze_traffic_patterns(self):
        """Analyze traffic patterns for anomalies"""
        logger.debug("ANOMALY", "Starting traffic pattern analysis...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        self._lock_ui(True)
        self._scan_banner("Analyzing Traffic Patterns", "Examining view patterns and traffic anomalies...")
        
        try:
            self.anomaly_results.clear()
            self.recommendations_display.clear()
            self.anomalies_table.setRowCount(0)
            
            self.anomaly_results.append("🚦 Starting traffic pattern analysis...")
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
                self.anomaly_results.append(f"📄 Fetching video page {page_count}...")
                
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
                    
                    self.anomaly_results.append(f"✅ Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                else:
                    self.anomaly_results.append(f"❌ Error on page {page_count}: {video_response.status_code}")
                    break
            
            if all_videos:
                self.anomaly_results.append(f"📊 Analyzing traffic patterns across {len(all_videos)} videos...")
                self.progress_bar.setValue(60)
                
                # Analyze traffic patterns
                traffic_anomalies = self.analyze_traffic_anomalies(all_videos)
                
                if traffic_anomalies:
                    self.populate_anomalies_table(traffic_anomalies)
                    self.anomaly_results.append(f"🚨 Found {len(traffic_anomalies)} traffic anomalies")
                    
                    # Calculate overall anomaly score
                    avg_confidence = sum(a['confidence'] for a in traffic_anomalies) / len(traffic_anomalies)
                    self.anomaly_score_label.setText(f"{avg_confidence:.1f}/100")
                    self.set_anomaly_score_style(avg_confidence)
                    
                    # Generate recommendations
                    self.generate_traffic_recommendations(traffic_anomalies)
                else:
                    self.anomaly_results.append("✅ No traffic anomalies detected")
                    self.anomaly_score_label.setText("0.0/100")
                    self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
            else:
                self.anomaly_results.append("❌ No videos found to analyze")
            
            self.progress_bar.setValue(100)
                
        except Exception as e:
            self.anomaly_results.append(f"❌ Error during traffic analysis: {e}")
        finally:
            # Re-enable UI
            self._lock_ui(False)
    
    def full_anomaly_scan(self):
        """Perform a comprehensive anomaly scan"""
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return

        self._lock_ui(True)
        self.anomaly_results.clear()
        self.recommendations_display.clear()
        self.anomalies_table.setRowCount(0)
        self._scan_banner("Full Anomaly Scan", "Running bots, engagement, and traffic modules...")

        try:
            # Option A: call subroutines that DON'T touch UI state/spinner/progress
            self.anomaly_results.append("🤖 Bot scan...")
            self.detect_bots()  # if you keep this, ensure detect_bots no longer shows/hides spinner or locks

            self.anomaly_results.append("📊 Engagement scan...")
            self.analyze_engagement_patterns()

            self.anomaly_results.append("🚦 Traffic scan...")
            self.analyze_traffic_patterns()

            self.anomaly_results.append("✅ Comprehensive anomaly scan completed")
        except Exception as e:
            self.anomaly_results.append(f"❌ Error during full scan: {e}")
        finally:
            self._lock_ui(False)
    
    def analyze_bot_patterns(self, videos):
        """
        Score per-video anomalies using multiple, explainable signals:
        - z-scores of engagement ratios vs. channel mean
        - Benford last-digit deviation on counts
        - Rolling median absolute deviation (MAD) for spikes
        Returns list[dict] rows for the table.
        """
        anomalies = []
        sens = self.sensitivity_slider.value()  # 1..10
        # thresholds scale with sensitivity (higher = more strict)
        z_thresh = max(1.5, 3.5 - (sens * 0.2))
        mad_thresh = max(2.0, 4.0 - (sens * 0.2))
        benf_thresh = max(0.05, 0.20 - (sens * 0.01))

        # 1) Build arrays
        views = [max(1, v.get('view_count',0)) for v in videos]
        likes = [v.get('like_count',0) for v in videos]
        cmts = [v.get('comment_count',0) for v in videos]
        shares = [v.get('share_count',0) for v in videos]
        lv = [l/v for l,v in zip(likes, views)]
        cv = [c/v for c,v in zip(cmts, views)]
        sv = [s/v for s,v in zip(shares, views)]

        def zscores(arr):
            import statistics as st
            mu = st.mean(arr) if arr else 0.0
            sd = st.pstdev(arr) if len(arr) > 1 else 0.0
            return [(0 if sd == 0 else (x - mu) / (sd + 1e-9)) for x in arr], mu, sd

        lv_z, lv_mu, lv_sd = zscores(lv)
        cv_z, cv_mu, cv_sd = zscores(cv)
        sv_z, sv_mu, sv_sd = zscores(sv)

        # 2) Benford last-digit (quick check)
        def last_digit_dist(xs):
            from collections import Counter
            cnt = Counter(int(str(int(x))[-1]) for x in xs if x >= 10)
            total = sum(cnt.values()) or 1
            return [cnt.get(d,0)/total for d in range(10)]
        expected = [0.119,0.113,0.109,0.104,0.100,0.097,0.093,0.090,0.088,0.087]  # rough
        def benford_divergence(xs):
            obs = last_digit_dist(xs)
            return sum(abs(o - e) for o,e in zip(obs, expected))

        benf_views = benford_divergence(views)
        benf_likes = benford_divergence(likes)
        benf_cmts = benford_divergence(cmts)
        benf_shares = benford_divergence(shares)
        benf_flag = any(b > benf_thresh for b in (benf_views, benf_likes, benf_cmts, benf_shares))

        # 3) Rolling MAD spikes on views
        def rolling_mad(xs, w=9):
            import statistics as st
            res = [0.0]*len(xs)
            for i in range(len(xs)):
                a = xs[max(0,i-w//2):min(len(xs), i+w//2+1)]
                med = st.median(a)
                mad = st.median([abs(x-med) for x in a]) + 1e-9
                res[i] = 0 if mad == 0 else abs(xs[i]-med)/mad
            return res
        views_mad = rolling_mad(views)

        # Compose per-video anomalies
        for i, v in enumerate(videos):
            vid = v.get('id','N/A')
            ev = []
            conf = 0

            if abs(lv_z[i]) >= z_thresh:
                ev.append(f"Like/View z={lv_z[i]:.2f} (μ={lv_mu:.3f},σ={lv_sd:.3f})")
                conf += min(30, 10+abs(lv_z[i])*5)
            if abs(cv_z[i]) >= z_thresh:
                ev.append(f"Comment/View z={cv_z[i]:.2f}")
                conf += min(25, 8+abs(cv_z[i])*4)
            if abs(sv_z[i]) >= z_thresh:
                ev.append(f"Share/View z={sv_z[i]:.2f}")
                conf += min(20, 6+abs(sv_z[i])*3)

            if views_mad[i] >= mad_thresh:
                ev.append(f"View spike MAD={views_mad[i]:.2f}")
                conf += min(25, 5+views_mad[i]*4)

            if benf_flag:
                ev.append("Benford last-digit divergence across counts")
                conf += 10

            if ev:
                anomalies.append({
                    'video_id': vid,
                    'anomaly_type': "Engagement/Traffic",
                    'severity': "HIGH" if conf >= 70 else ("MEDIUM" if conf >= 40 else "LOW"),
                    'evidence': " | ".join(ev),
                    'confidence': float(min(100, conf))
                })

        return anomalies
    
    def analyze_engagement_anomalies(self, videos):
        """Analyze engagement patterns for anomalies"""
        anomalies = []
        sensitivity = self.sensitivity_slider.value()
        
        if len(videos) < 3:
            return anomalies  # Need at least 3 videos for pattern analysis
        
        # Calculate engagement statistics across all videos
        engagement_ratios = []
        for video in videos:
            view_count = video.get('view_count', 0)
            if view_count > 0:
                like_ratio = video.get('like_count', 0) / view_count
                comment_ratio = video.get('comment_count', 0) / view_count
                share_ratio = video.get('share_count', 0) / view_count
                engagement_ratios.append({
                    'video_id': video.get('id'),
                    'like_ratio': like_ratio,
                    'comment_ratio': comment_ratio,
                    'share_ratio': share_ratio,
                    'total_engagement': like_ratio + comment_ratio + share_ratio
                })
        
        if not engagement_ratios:
            return anomalies
        
        # Calculate averages and standard deviations
        like_ratios = [r['like_ratio'] for r in engagement_ratios]
        comment_ratios = [r['comment_ratio'] for r in engagement_ratios]
        share_ratios = [r['share_ratio'] for r in engagement_ratios]
        total_engagements = [r['total_engagement'] for r in engagement_ratios]
        
        avg_like = statistics.mean(like_ratios)
        avg_comment = statistics.mean(comment_ratios)
        avg_share = statistics.mean(share_ratios)
        avg_total = statistics.mean(total_engagements)
        
        std_like = statistics.stdev(like_ratios) if len(like_ratios) > 1 else 0
        std_comment = statistics.stdev(comment_ratios) if len(comment_ratios) > 1 else 0
        std_share = statistics.stdev(share_ratios) if len(share_ratios) > 1 else 0
        std_total = statistics.stdev(total_engagements) if len(total_engagements) > 1 else 0
        
        # Detect anomalies (values more than 2 standard deviations from mean)
        threshold = 2 * (sensitivity / 5)  # Adjust threshold based on sensitivity
        
        for ratio in engagement_ratios:
            indicators = []
            confidence = 0
            
            # Check for like ratio anomalies
            if std_like > 0 and abs(ratio['like_ratio'] - avg_like) > threshold * std_like:
                indicators.append(f"Like ratio anomaly: {ratio['like_ratio']:.2%} vs avg {avg_like:.2%}")
                confidence += 20
            
            # Check for comment ratio anomalies
            if std_comment > 0 and abs(ratio['comment_ratio'] - avg_comment) > threshold * std_comment:
                indicators.append(f"Comment ratio anomaly: {ratio['comment_ratio']:.2%} vs avg {avg_comment:.2%}")
                confidence += 20
            
            # Check for share ratio anomalies
            if std_share > 0 and abs(ratio['share_ratio'] - avg_share) > threshold * std_share:
                indicators.append(f"Share ratio anomaly: {ratio['share_ratio']:.2%} vs avg {avg_share:.2%}")
                confidence += 20
            
            # Check for total engagement anomalies
            if std_total > 0 and abs(ratio['total_engagement'] - avg_total) > threshold * std_total:
                indicators.append(f"Total engagement anomaly: {ratio['total_engagement']:.2%} vs avg {avg_total:.2%}")
                confidence += 25
            
            if indicators and confidence > 30:
                anomalies.append({
                    'video_id': ratio['video_id'],
                    'anomaly_type': 'Engagement Pattern',
                    'severity': 'High' if confidence > 70 else 'Medium' if confidence > 50 else 'Low',
                    'evidence': '; '.join(indicators),
                    'confidence': confidence
                })
        
        return anomalies
    
    def analyze_traffic_anomalies(self, videos):
        """Analyze traffic patterns for anomalies"""
        anomalies = []
        sensitivity = self.sensitivity_slider.value()
        
        if len(videos) < 3:
            return anomalies
        
        # Calculate view count statistics
        view_counts = [v.get('view_count', 0) for v in videos]
        avg_views = statistics.mean(view_counts)
        std_views = statistics.stdev(view_counts) if len(view_counts) > 1 else 0
        
        # Detect traffic spikes and drops
        threshold = 2 * (sensitivity / 5)
        
        for video in videos:
            view_count = video.get('view_count', 0)
            indicators = []
            confidence = 0
            
            # Check for traffic spikes
            if std_views > 0 and view_count > avg_views + threshold * std_views:
                spike_factor = view_count / avg_views
                indicators.append(f"Traffic spike: {view_count:,} views ({spike_factor:.1f}x average)")
                confidence += 30
            
            # Check for traffic drops
            elif std_views > 0 and view_count < avg_views - threshold * std_views:
                drop_factor = avg_views / view_count if view_count > 0 else float('inf')
                indicators.append(f"Traffic drop: {view_count:,} views ({drop_factor:.1f}x below average)")
                confidence += 25
            
            # Check for suspicious view patterns
            if view_count > 0:
                like_count = video.get('like_count', 0)
                comment_count = video.get('comment_count', 0)
                share_count = video.get('share_count', 0)
                
                # Views with no engagement (suspicious)
                if like_count == 0 and comment_count == 0 and share_count == 0:
                    indicators.append("Views with zero engagement (suspicious)")
                    confidence += 20
                
                # Unusually high view-to-engagement ratio
                total_engagement = like_count + comment_count + share_count
                if total_engagement > 0:
                    engagement_ratio = total_engagement / view_count
                    if engagement_ratio < 0.001:  # Less than 0.1% engagement
                        indicators.append(f"Very low engagement ratio: {engagement_ratio:.3%}")
                        confidence += 15
            
            if indicators and confidence > 30:
                anomalies.append({
                    'video_id': video.get('id', 'Unknown'),
                    'anomaly_type': 'Traffic Pattern',
                    'severity': 'High' if confidence > 70 else 'Medium' if confidence > 50 else 'Low',
                    'evidence': '; '.join(indicators),
                    'confidence': confidence
                })
        
        return anomalies
    
    def populate_anomalies_table(self, anomalies):
        """Populate the anomalies table with found issues"""
        self.anomalies_table.setRowCount(len(anomalies))
        
        for row, anomaly in enumerate(anomalies):
            self.anomalies_table.setItem(row, 0, QTableWidgetItem(str(anomaly['video_id'])))
            self.anomalies_table.setItem(row, 1, QTableWidgetItem(anomaly['anomaly_type']))
            self.anomalies_table.setItem(row, 2, QTableWidgetItem(anomaly['severity']))
            
            # Evidence column with proper wrapping
            item = QTableWidgetItem(anomaly['evidence'])
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            self.anomalies_table.setItem(row, 3, item)
            
            self.anomalies_table.setItem(row, 4, QTableWidgetItem(f"{anomaly['confidence']:.1f}%"))
        
        # Resize rows to content and ensure proper wrapping
        self.anomalies_table.resizeRowsToContents()
        self.anomalies_table.setWordWrap(True)
    
    def set_anomaly_score_style(self, score):
        """Set the style for the anomaly score based on value"""
        if score > 70:
            self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #F44336;")
        elif score > 40:
            self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FF9800;")
        else:
            self.anomaly_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4CAF50;")
    
    def generate_bot_response_recommendations(self, anomalies):
        """Generate recommendations for bot detection"""
        self.recommendations_display.append("🤖 BOT DETECTION RESPONSE RECOMMENDATIONS:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Report suspicious accounts to TikTok")
        self.recommendations_display.append("   • Block obvious bot accounts")
        self.recommendations_display.append("   • Review and moderate comments")
        self.recommendations_display.append("   • Enable comment filtering")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 MONITORING STRATEGIES:")
        self.recommendations_display.append("   • Monitor engagement ratios regularly")
        self.recommendations_display.append("   • Track follower growth patterns")
        self.recommendations_display.append("   • Watch for sudden engagement spikes")
        self.recommendations_display.append("   • Analyze comment patterns for bot-like behavior")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ PREVENTION MEASURES:")
        self.recommendations_display.append("   • Use CAPTCHA for comments if available")
        self.recommendations_display.append("   • Moderate comments before they appear")
        self.recommendations_display.append("   • Report bot networks to TikTok")
        self.recommendations_display.append("   • Consider using third-party bot detection tools")
    
    def generate_engagement_recommendations(self, anomalies):
        """Generate recommendations for engagement anomalies"""
        self.recommendations_display.append("📊 ENGAGEMENT ANOMALY RESPONSE:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Investigate videos with unusual engagement")
        self.recommendations_display.append("   • Check if engagement is organic or manipulated")
        self.recommendations_display.append("   • Review content quality and timing")
        self.recommendations_display.append("   • Consider content strategy adjustments")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 ANALYSIS STRATEGIES:")
        self.recommendations_display.append("   • Compare engagement across similar content")
        self.recommendations_display.append("   • Analyze posting time and frequency")
        self.recommendations_display.append("   • Review hashtag and caption strategies")
        self.recommendations_display.append("   • Monitor competitor engagement patterns")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ OPTIMIZATION MEASURES:")
        self.recommendations_display.append("   • A/B test different content formats")
        self.recommendations_display.append("   • Optimize posting schedule")
        self.recommendations_display.append("   • Improve content quality and relevance")
        self.recommendations_display.append("   • Engage with your audience more actively")
    
    def generate_traffic_recommendations(self, anomalies):
        """Generate recommendations for traffic anomalies"""
        self.recommendations_display.append("🚦 TRAFFIC ANOMALY RESPONSE:")
        self.recommendations_display.append("")
        self.recommendations_display.append("🚨 IMMEDIATE ACTIONS:")
        self.recommendations_display.append("   • Investigate traffic spike sources")
        self.recommendations_display.append("   • Check for external promotion or mentions")
        self.recommendations_display.append("   • Review content performance metrics")
        self.recommendations_display.append("   • Monitor for potential viral content")
        self.recommendations_display.append("")
        self.recommendations_display.append("🔍 ANALYSIS STRATEGIES:")
        self.recommendations_display.append("   • Track traffic sources and referrers")
        self.recommendations_display.append("   • Analyze viewer demographics")
        self.recommendations_display.append("   • Monitor watch time and completion rates")
        self.recommendations_display.append("   • Check for trending hashtag usage")
        self.recommendations_display.append("")
        self.recommendations_display.append("🛡️ OPTIMIZATION MEASURES:")
        self.recommendations_display.append("   • Capitalize on viral content opportunities")
        self.recommendations_display.append("   • Optimize content for better retention")
        self.recommendations_display.append("   • Use trending hashtags strategically")
        self.recommendations_display.append("   • Engage with viewers during traffic spikes")
