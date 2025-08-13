"""
Loading Spinner Component
Provides a reusable loading spinner for API requests and long-running operations
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont


class LoadingSpinner(QWidget):
    """Reusable loading spinner with progress bar and status text"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.hide()
        
    def setup_ui(self):
        """Setup the loading spinner UI"""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Loading text
        self.loading_label = QLabel("Loading...")
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(self.loading_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setFixedHeight(20)
        layout.addWidget(self.progress_bar)
        
        # Status text
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setMaximumWidth(300)
        layout.addWidget(self.status_label)
        
        # Set fixed size
        self.setFixedSize(350, 120)
        
    def show_loading(self, message="Loading...", status=""):
        """Show the loading spinner with custom message and status"""
        self.loading_label.setText(message)
        self.status_label.setText(status)
        self.show()
        
    def update_status(self, status):
        """Update the status text"""
        self.status_label.setText(status)
        
    def hide_loading(self):
        """Hide the loading spinner"""
        self.hide()


class LoadingOverlay(QWidget):
    """Full-screen loading overlay that blocks interaction"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.hide()
        
    def setup_ui(self):
        """Setup the loading overlay UI"""
        # Make it cover the entire parent widget
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(0, 0, 0, 180);
                color: white;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Loading text
        self.loading_label = QLabel("Loading...")
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.loading_label.setStyleSheet("color: white;")
        layout.addWidget(self.loading_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setFixedHeight(25)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid white;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Status text
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setMaximumWidth(400)
        self.status_label.setStyleSheet("color: white;")
        layout.addWidget(self.status_label)
        
    def show_loading(self, message="Loading...", status=""):
        """Show the loading overlay with custom message and status"""
        self.loading_label.setText(message)
        self.status_label.setText(status)
        self.show()
        
        # Resize to cover parent
        if self.parent():
            self.resize(self.parent().size())
        
    def update_status(self, status):
        """Update the status text"""
        self.status_label.setText(status)
        
    def hide_loading(self):
        """Hide the loading overlay"""
        self.hide()
        
    def resizeEvent(self, event):
        """Handle resize events to maintain full coverage"""
        super().resizeEvent(event)
        if self.parent():
            self.resize(self.parent().size())
