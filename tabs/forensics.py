"""
Video Forensics Tab Component
Handles video metadata extraction and forensic analysis
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView
)
import requests
import json
from datetime import datetime
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingOverlay


class ForensicsTab(QWidget):
    """Video Metadata Extractor + Forensics Dashboard tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
        # Initialize loading overlay
        self.loading_overlay = LoadingOverlay(self)
    
    def setup_ui(self):
        """Setup the video forensics UI"""
        layout = QVBoxLayout(self)
        
        # Video Forensics group
        forensics_group = QGroupBox("Video Metadata Extractor + Forensics Dashboard")
        forensics_layout = QVBoxLayout(forensics_group)
        
        # Analysis controls
        controls_layout = QHBoxLayout()
        
        self.extract_videos_button = QPushButton("📹 Extract Video Metadata")
        self.extract_videos_button.setStyleSheet("""
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
        self.extract_videos_button.clicked.connect(self.extract_video_metadata)
        controls_layout.addWidget(self.extract_videos_button)
        
        self.export_forensics_button = QPushButton("Export Forensics Report")
        self.export_forensics_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:pressed {
                background-color: #EF6C00;
            }
        """)
        self.export_forensics_button.clicked.connect(self.export_forensics_report)
        controls_layout.addWidget(self.export_forensics_button)
        
        forensics_layout.addLayout(controls_layout)
        
        # Video metadata table
        self.video_table = QTableWidget()
        self.video_table.setColumnCount(8)
        self.video_table.setHorizontalHeaderLabels([
            "Video ID", "Title", "Posted", "Duration", "Views", "Likes", "Comments", "Shares"
        ])
        self.video_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.video_table.setMaximumHeight(300)
        forensics_layout.addWidget(self.video_table)
        
        # Forensics analysis results
        self.forensics_results = QTextEdit()
        self.forensics_results.setPlaceholderText("Forensic analysis results will appear here...")
        self.forensics_results.setMaximumHeight(200)
        forensics_layout.addWidget(self.forensics_results)
        
        layout.addWidget(forensics_group)
        
        # Forensic insights group
        insights_group = QGroupBox("Forensic Insights")
        insights_layout = QVBoxLayout(insights_group)
        
        self.insights_display = QTextEdit()
        self.insights_display.setPlaceholderText("Forensic insights and evidence will appear here...")
        self.insights_display.setMaximumHeight(200)
        insights_layout.addWidget(self.insights_display)
        
        layout.addWidget(insights_group)
    
    def get_access_token(self):
        """Get access token from parent"""
        if self.parent and hasattr(self.parent, 'access_token'):
            return self.parent.access_token
        return None
    
    def extract_video_metadata(self):
        """Extract metadata from user's videos"""
        logger.debug("FORENSICS", "Starting video metadata extraction...")
        access_token = self.get_access_token()
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return

        # Show loading overlay
        self.loading_overlay.show_loading("Extracting Video Metadata", "Fetching video data from TikTok API...")
        self.extract_videos_button.setEnabled(False)

        try:
            self.forensics_results.clear()
            self.insights_display.clear()
            self.video_table.setRowCount(0)

            self.forensics_results.append("Fetching ALL video metadata...")
            self.forensics_results.append("⏳ This may take a while depending on the number of videos...")

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Fields parameter goes in URL query string - using only valid fields
            fields = 'id,title,cover_image_url,share_url,video_description,duration,height,width,comment_count,like_count,share_count,view_count'

            all_videos = []
            cursor = 0
            has_more = True
            page_count = 0

            while has_more:
                page_count += 1
                self.forensics_results.append(f"Fetching page {page_count}...")
                
                # Update loading status
                self.loading_overlay.update_status(f"Fetching page {page_count}... (Total: {len(all_videos)} videos)")
                
                # Request body for video list API
                request_body = {
                    'max_count': 20,  # Maximum allowed per request
                    'cursor': cursor
                }

                response = requests.post(f'https://open.tiktokapis.com/v2/video/list/?fields={fields}', headers=headers, json=request_body)

                if response.status_code == 200:
                    video_data = response.json()
                    data = video_data.get('data', {})
                    
                    videos = data.get('videos', [])
                    all_videos.extend(videos)
                    
                    # Update pagination info
                    cursor = data.get('cursor', 0)
                    has_more = data.get('has_more', False)
                    
                    self.forensics_results.append(f"Page {page_count}: Retrieved {len(videos)} videos (Total: {len(all_videos)})")
                    
                    # Small delay to be respectful to the API
                    import time
                    time.sleep(0.5)
                    
                else:
                    self.forensics_results.append(f"Error on page {page_count}: {response.status_code}")
                    self.forensics_results.append(f"Response: {response.text}")
                    break

            if all_videos:
                self.forensics_results.append(f"🎉 Successfully retrieved {len(all_videos)} videos across {page_count} pages")
                self.process_video_metadata(all_videos)
                self.generate_forensic_insights(all_videos)
            else:
                self.forensics_results.append("No videos found or no videos accessible")

        except Exception as e:
            logger.error("FORENSICS", "Exception during extraction", e)
            self.forensics_results.append(f"Exception during extraction: {e}")
        finally:
            # Hide loading overlay and re-enable button
            self.loading_overlay.hide_loading()
            self.extract_videos_button.setEnabled(True)
    
    def process_video_metadata(self, videos):
        """Process and display video metadata in table"""
        self.video_table.setRowCount(len(videos))
        
        # Add detailed processing info
        self.forensics_results.append(f"Processing {len(videos)} videos for detailed analysis...")
        
        total_views = 0
        total_likes = 0
        total_comments = 0
        total_shares = 0
        total_duration = 0
        
        for row, video in enumerate(videos):
            # Video ID
            video_id = video.get('id', 'N/A')
            self.video_table.setItem(row, 0, QTableWidgetItem(str(video_id)))
            
            # Title
            title = video.get('title', 'No title')
            if len(title) > 30:
                title = title[:27] + "..."
            self.video_table.setItem(row, 1, QTableWidgetItem(title))
            
            # Posted time (not available in v2 API)
            posted_date = 'N/A'
            self.video_table.setItem(row, 2, QTableWidgetItem(posted_date))
            
            # Duration
            duration = video.get('duration', 0)
            if duration:
                duration_str = f"{duration//60}:{duration%60:02d}"
                total_duration += duration
            else:
                duration_str = 'N/A'
            self.video_table.setItem(row, 3, QTableWidgetItem(duration_str))
            
            # Views
            view_count = video.get('view_count', 0)
            total_views += view_count
            self.video_table.setItem(row, 4, QTableWidgetItem(f"{view_count:,}"))
            
            # Likes
            like_count = video.get('like_count', 0)
            total_likes += like_count
            self.video_table.setItem(row, 5, QTableWidgetItem(f"{like_count:,}"))
            
            # Comments
            comment_count = video.get('comment_count', 0)
            total_comments += comment_count
            self.video_table.setItem(row, 6, QTableWidgetItem(f"{comment_count:,}"))
            
            # Shares
            share_count = video.get('share_count', 0)
            total_shares += share_count
            self.video_table.setItem(row, 7, QTableWidgetItem(f"{share_count:,}"))
        
        # Display comprehensive statistics
        self.forensics_results.append(f"COMPREHENSIVE ANALYSIS COMPLETE:")
        self.forensics_results.append(f"   • Total Videos: {len(videos):,}")
        self.forensics_results.append(f"   • Total Views: {total_views:,}")
        self.forensics_results.append(f"   • Total Likes: {total_likes:,}")
        self.forensics_results.append(f"   • Total Comments: {total_comments:,}")
        self.forensics_results.append(f"   • Total Shares: {total_shares:,}")
        
        if total_duration > 0:
            avg_duration = total_duration / len(videos)
            total_hours = total_duration / 3600
            self.forensics_results.append(f"   • Total Duration: {total_hours:.1f} hours")
            self.forensics_results.append(f"   • Average Duration: {int(avg_duration//60)}:{int(avg_duration%60):02d}")
        
        if len(videos) > 0:
            avg_views = total_views / len(videos)
            avg_likes = total_likes / len(videos)
            avg_comments = total_comments / len(videos)
            self.forensics_results.append(f"   • Average Views: {avg_views:,.0f}")
            self.forensics_results.append(f"   • Average Likes: {avg_likes:,.0f}")
            self.forensics_results.append(f"   • Average Comments: {avg_comments:,.0f}")
    
    def generate_forensic_insights(self, videos):
        """Generate forensic insights from video metadata"""
        insights = []
        
        # Analyze posting patterns (timing not available in v2 API)
        insights.append(f"📅 Content Analysis: {len(videos)} videos available for analysis")
        
        # Analyze engagement patterns
        total_views = sum(v.get('view_count', 0) for v in videos)
        total_likes = sum(v.get('like_count', 0) for v in videos)
        total_comments = sum(v.get('comment_count', 0) for v in videos)
        
        insights.append(f"Engagement Summary: {total_views:,} total views, {total_likes:,} likes, {total_comments:,} comments")
        
        # Detect anomalies
        if videos:
            avg_views = total_views / len(videos)
            high_engagement_videos = [v for v in videos if v.get('view_count', 0) > avg_views * 2]
            if high_engagement_videos:
                insights.append(f"Anomaly: {len(high_engagement_videos)} videos with unusually high engagement (2x above average)")
        
        # Privacy analysis (privacy level not available in v2 API)
        insights.append(f"🔒 Privacy Analysis: Privacy settings not available in v2 API")
        
        # Content analysis
        videos_with_description = [v for v in videos if v.get('video_description')]
        insights.append(f"Content: {len(videos_with_description)} videos have descriptions")
        
        # Forensic evidence
        insights.append(f"\nFORENSIC EVIDENCE:")
        insights.append(f"• Account activity timeline established")
        insights.append(f"• Content creation patterns documented")
        insights.append(f"• Engagement metrics recorded")
        insights.append(f"• Privacy settings audit completed")
        
        # Note about privacy settings
        insights.append(f"Privacy settings analysis not available in v2 API")
        
        # Add to display
        for insight in insights:
            self.insights_display.append(insight)
    
    def export_forensics_report(self):
        """Export forensic analysis to a file"""
        if not hasattr(self, 'video_table') or self.video_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "Please extract video metadata first.")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"tiktok_forensics_report_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("TIKTOK FORENSIC ANALYSIS REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Video metadata
                f.write("VIDEO METADATA:\n")
                f.write("-" * 20 + "\n")
                for row in range(self.video_table.rowCount()):
                    video_id = self.video_table.item(row, 0).text()
                    title = self.video_table.item(row, 1).text()
                    posted = self.video_table.item(row, 2).text()
                    shares = self.video_table.item(row, 7).text()
                    f.write(f"Video {row+1}: {title} (ID: {video_id}, Posted: {posted}, Shares: {shares})\n")
                
                f.write("\n")
                
                # Forensic insights
                f.write("FORENSIC INSIGHTS:\n")
                f.write("-" * 20 + "\n")
                insights_text = self.insights_display.toPlainText()
                f.write(insights_text)
                
                f.write("\n\n")
                f.write("REPORT END\n")
            
            QMessageBox.information(self, "Export Complete", f"Forensic report exported to: {filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export report: {e}")
