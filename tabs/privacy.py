"""
Privacy Analysis Tab Component
Combines general privacy analysis and geolocation analysis in sub-tabs
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget
)
from .privacy_general import PrivacyGeneralTab
from .privacy_geolocation import PrivacyGeolocationTab


class PrivacyTab(QWidget):
    """Privacy Analysis tab with sub-tabs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the privacy analysis UI with sub-tabs"""
        layout = QVBoxLayout(self)
        
        # Create tab widget for privacy sub-tabs
        privacy_tabs = QTabWidget()
        
        # Create sub-tabs
        self.general_tab = PrivacyGeneralTab(self)
        self.geolocation_tab = PrivacyGeolocationTab(self)
        
        # Add sub-tabs
        privacy_tabs.addTab(self.general_tab, "🛡️ General Privacy")
        privacy_tabs.addTab(self.geolocation_tab, "📍 Geolocation")
        
        layout.addWidget(privacy_tabs)
