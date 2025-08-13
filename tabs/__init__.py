"""
TikTok Toolkit Tab Components Package
Contains all the tab components for the main application
"""

from .main import AuthTab
from .privacy import PrivacyTab
from .forensics import ForensicsTab
from .impersonation import ImpersonationTab
from .anomaly import AnomalyTab
from .stalkerware import StalkerwareTab

__all__ = ['AuthTab', 'PrivacyTab', 'ForensicsTab', 'ImpersonationTab', 'AnomalyTab', 'StalkerwareTab']
