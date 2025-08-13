"""
Geolocation Privacy Analysis Tab Component
Handles location-based privacy analysis and exposure detection
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, 
    QLabel, QTextEdit, QMessageBox
)
import requests
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, unquote
import math
import time
from logger import logger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from loading_spinner import LoadingSpinner
try:
    from geotext import GeoText  # pip install geotext
except Exception:
    GeoText = None

try:
    import pyap  # pip install pyap  (US/CA/UK address parsing)
except Exception:
    pyap = None


@dataclass
class LocationHit:
    kind: str
    value: str
    context: str
    confidence: float
    normalized: str

    def key(self) -> str:
        return f"{self.kind}|{self.normalized}"

    def __str__(self) -> str:
        # how it renders in the results pane
        return f"[{self.kind} | {int(self.confidence*100)}%] {self.value} — {self.context}"


class PrivacyGeolocationTab(QWidget):
    """Geolocation Privacy Analysis tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._geo_cache = {}   # { text_lower: bool_is_geo }
        self._geo_last = 0.0   # for 1 req/sec throttle

        self.setup_ui()
        
        # Initialize loading spinner
        self.loading_spinner = LoadingSpinner(self)
    
    def _has_real_geo(self, hits):
        return any(h.kind in {'coords','address','map_link','city','country','zip','hashtag_geo'} for h in hits)

    
    def _geocode_ok(self, q: str, timeout=5) -> bool:
        """Forward geocode q with Nominatim (1 req/sec). Cache results (True/False)."""
        tl = (q or "").strip().lower()
        if not tl:
            return False
        if tl in self._geo_cache:
            return self._geo_cache[tl]
        try:
            import time, requests as _r
            # throttle
            now = time.time()
            if now - self._geo_last < 1.05:
                time.sleep(1.1 - (now - self._geo_last))
            self._geo_last = time.time()
            r = _r.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": q, "format": "jsonv2", "limit": 1},
                headers={"User-Agent": "PrivacyAnalyzer/1.0"},
                timeout=timeout,
            )
            ok = False
            if r.ok:
                j = r.json()
                ok = bool(j and j[0].get("lat") and j[0].get("lon"))
            self._geo_cache[tl] = ok
            return ok
        except Exception:
            self._geo_cache[tl] = False
            return False

    def setup_ui(self):
        """Setup the geolocation privacy analysis UI"""
        layout = QVBoxLayout(self)
        
        # Geolocation Analysis group
        geo_group = QGroupBox("Geolocation Privacy Analysis")
        geo_layout = QVBoxLayout(geo_group)
        
        # Analysis button
        self.analyze_location_button = QPushButton("📍 Analyze Geolocation Data")
        self.analyze_location_button.setStyleSheet("""
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
        self.analyze_location_button.clicked.connect(self.analyze_geolocation_data)
        geo_layout.addWidget(self.analyze_location_button)
        
        # Location privacy score display
        score_layout = QHBoxLayout()
        score_layout.addWidget(QLabel("Location Privacy Score:"))
        self.location_score_label = QLabel("Not analyzed")
        self.location_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #666;")
        score_layout.addWidget(self.location_score_label)
        score_layout.addStretch()
        geo_layout.addLayout(score_layout)
        
        # Analysis results
        self.geo_results = QTextEdit()
        self.geo_results.setPlaceholderText("Geolocation analysis results will appear here...")
        self.geo_results.setMaximumHeight(200)
        geo_layout.addWidget(self.geo_results)
        
        layout.addWidget(geo_group)
        
        # Recommendations group
        recommendations_group = QGroupBox("Location Privacy Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_display = QTextEdit()
        self.recommendations_display.setPlaceholderText("Location privacy recommendations will appear here...")
        self.recommendations_display.setMaximumHeight(200)
        recommendations_layout.addWidget(self.recommendations_display)
        
        layout.addWidget(recommendations_group)
    
    def get_access_token(self):
        """Get access token from main application"""
        logger.debug("PRIVACY_GEO", f"Parent hierarchy: parent={self.parent}, parent.parent={getattr(self.parent, 'parent', None) if self.parent else None}")
        if self.parent and hasattr(self.parent, 'parent') and self.parent.parent:
            token = self.parent.parent.access_token
            logger.debug("PRIVACY_GEO", f"Token from main app: {'Yes' if token else 'No'}")
            return token
        logger.debug("PRIVACY_GEO", "Could not access main application token")
        return None
    
    def analyze_geolocation_data(self):
        """Analyze geolocation data and location-based privacy risks"""
        logger.debug("PRIVACY_GEO", "Starting geolocation analysis...")
        access_token = self.get_access_token()
        logger.debug("PRIVACY_GEO", f"Access token retrieved: {'Yes' if access_token else 'No'}")
        if not access_token:
            QMessageBox.warning(self, "No Access Token", "Please authenticate first.")
            return
            
        # Show loading spinner
        self.loading_spinner.show_loading("Analyzing Geolocation Data", "Checking profile and video content for location indicators...")
        self.analyze_location_button.setEnabled(False)

        try:
            self.geo_results.clear()
            self.recommendations_display.clear()

            self.geo_results.append("📍 Analyzing geolocation data and location-based privacy risks...")
            self.geo_results.append("🔍 Checking profile data, video metadata, and content for location indicators...")

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Get user info
            user_response = requests.get('https://open.tiktokapis.com/v2/user/info/',
                                       headers=headers,
                                       params={'fields': 'open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count'})

            location_risks = []
            location_data = []
            geo_score = 100  # Start with perfect score

            if user_response.status_code == 200:
                user_data = user_response.json()
                user = user_data.get('data', {}).get('user', {})

                # Analyze bio description for location indicators
                bio_description = user.get('bio_description', '')
                if bio_description:
                    self.geo_results.append(f"Analyzing bio: {bio_description}")
                    location_indicators = self.extract_location_indicators(bio_description)
                    if location_indicators:
                        location_data.extend(location_indicators)
                        for h in location_indicators:
                            geo_score -= int(self._penalty(h.kind) * h.confidence)
                        if self._has_real_geo(location_indicators):  # Gate the risk
                            location_risks.append(
                                "Bio contains location indicators: " +
                                ", ".join(str(h) for h in location_indicators[:5])
                            )

                # Get video data to check for location metadata
                self.geo_results.append("Checking video metadata for location data...")

                # Fetch videos to check for location data
                fields = 'id,title,video_description,share_url'
                all_videos = []
                cursor = 0
                has_more = True
                page_count = 0

                while has_more and page_count < 3:  # Limit to first 3 pages for performance
                    page_count += 1
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

                        # Analyze video descriptions for location data
                        for video in videos:
                            title = video.get('title', '')
                            description = video.get('video_description', '')

                            if title:
                                title_locations = self.extract_location_indicators(title)
                                if title_locations:
                                    location_data.extend(title_locations)
                                    for h in title_locations:
                                        geo_score -= int(self._penalty(h.kind) * h.confidence * 0.5)  # Reduced penalty for video content
                                    if self._has_real_geo(title_locations):  # Gate the risk
                                        location_risks.append(f"Video title contains location: {title[:50]}...")

                            if description:
                                desc_locations = self.extract_location_indicators(description)
                                if desc_locations:
                                    location_data.extend(desc_locations)
                                    for h in desc_locations:
                                        geo_score -= int(self._penalty(h.kind) * h.confidence * 0.5)  # Reduced penalty for video content
                                    if self._has_real_geo(desc_locations):  # Gate the risk
                                        location_risks.append(f"Video description contains location: {description[:50]}...")
                    else:
                        break

                self.geo_results.append(f"Analyzed {len(all_videos)} videos for location data")

            else:
                self.geo_results.append(f"❌ Error fetching user data: {user_response.status_code}")
                return

            # Generate location analysis results
            self.geo_results.append(f"\nGEOLOCATION ANALYSIS RESULTS:")
            self.geo_results.append(f"Location Privacy Score: {geo_score}/100")

            if location_data:
                # dedupe, keep highest-confidence for each normalized key
                uniq = {}
                for h in location_data:
                    k = h.key()
                    if k not in uniq or h.confidence > uniq[k].confidence:
                        uniq[k] = h
                unique_locations = list(uniq.values())

                self.geo_results.append(f"Found {len(unique_locations)} unique location indicators:")
                for h in unique_locations[:50]:
                    self.geo_results.append(f"   • {str(h)}")

                self.geo_results.append(f"\nLOCATION PRIVACY RISKS:")
                for risk in location_risks:
                    self.geo_results.append(f"   {risk}")

                # Generate location-specific recommendations
                self.recommendations_display.append("LOCATION PRIVACY RECOMMENDATIONS:")
                self.recommendations_display.append("CRITICAL: Your content contains location data that can be used for:")
                self.recommendations_display.append("   • Physical location tracking")
                self.recommendations_display.append("   • Pattern analysis (home/work locations)")
                self.recommendations_display.append("   • Social engineering attacks")
                self.recommendations_display.append("   • Stalking and harassment")
                self.recommendations_display.append("")
                self.recommendations_display.append("IMMEDIATE ACTIONS:")
                self.recommendations_display.append("   • Remove location indicators from bio")
                self.recommendations_display.append("   • Edit video descriptions to remove location data")
                self.recommendations_display.append("   • Avoid posting real-time location updates")
                self.recommendations_display.append("   • Use generic location references")
                self.recommendations_display.append("   • Consider using VPN when posting")
                self.recommendations_display.append("   • Review old content for location data")
                self.recommendations_display.append("   • Enable location privacy settings")
                self.recommendations_display.append("")
                self.recommendations_display.append("OSINT IMPACT:")
                self.recommendations_display.append("   • Location data is easily searchable")
                self.recommendations_display.append("   • Can be combined with other public data")
                self.recommendations_display.append("   • Enables physical security risks")
                self.recommendations_display.append("   • Reduces anonymity significantly")

            else:
                self.geo_results.append("No location indicators found in analyzed content")
                self.recommendations_display.append("LOCATION PRIVACY STATUS: GOOD")
                self.recommendations_display.append("No location indicators detected in your content")
                self.recommendations_display.append("")
                self.recommendations_display.append("CONTINUE TO:")
                self.recommendations_display.append("   • Avoid posting specific locations")
                self.recommendations_display.append("   • Use generic location references")
                self.recommendations_display.append("   • Be mindful of background details in videos")
                self.recommendations_display.append("   • Review content before posting")

            # Clamp the score to ensure it never goes below zero
            geo_score = max(0, geo_score)
            self.location_score_label.setText(f"{geo_score}/100")
            self.location_score_label.setStyleSheet(self.get_score_style(geo_score))

        except Exception as e:
            logger.error("PRIVACY_GEO", "Error during geolocation analysis", e)
            self.geo_results.append(f"❌ Error during geolocation analysis: {e}")
        finally:
            # Hide loading spinner and re-enable button
            self.loading_spinner.hide_loading()
            self.analyze_location_button.setEnabled(True)

    def extract_location_indicators(self, text: str) -> list[LocationHit]:
        """High-precision geolocation extraction with confidence + dedupe."""
        if not text:
            return []

        raw = text
        tl = text.lower()
        hits: list[LocationHit] = []

        # 1) Map links (Google/Apple/OSM/Bing) — capture q=, query=, ll=, path
        for token in re.findall(r'https?://\S+', raw):
            try:
                u = urlparse(token)
                host = u.netloc.lower()
                if any(h in host for h in (
                    'maps.google.', 'goo.gl', 'maps.apple.', 'openstreetmap.', 'osm.', 'bing.com')):
                    q = parse_qs(u.query)
                    candidates = [
                        q.get('q', [''])[0], q.get('query', [''])[0], q.get('destination', [''])[0],
                        q.get('ll', [''])[0], unquote(u.path)
                    ]
                    val = next((c for c in candidates if c), '')
                    if val:
                        norm = val.strip().lower()
                        hits.append(LocationHit('map_link', val.strip(), token[:100], 0.9, norm))
            except Exception:
                pass

        # 2) Decimal coords (lat,lon)
        for m in re.finditer(r'(?P<lat>[+-]?\d{1,2}\.\d{3,})\s*,\s*(?P<lon>[+-]?\d{1,3}\.\d{3,})', raw):
            try:
                lat, lon = float(m.group('lat')), float(m.group('lon'))
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    norm = f"{lat:.5f},{lon:.5f}"
                    ctx = self._context_snippet(raw, m.start(), m.end())
                    hits.append(LocationHit('coords', norm, ctx, 0.95, norm))
            except Exception:
                pass

        # 3) DMS coords (40°42'46"N 74°0'21"W)
        dms = re.finditer(
            r'(\d{1,2})[°\s]\s?(\d{1,2})[\'\s]\s?(\d{1,2})["\s]?\s?([NS])[,;\s]+'
            r'(\d{1,3})[°\s]\s?(\d{1,2})[\'\s]\s?(\d{1,2})["\s]?\s?([EW])', raw, re.I)
        for m in dms:
            try:
                lat = int(m.group(1)) + int(m.group(2))/60 + int(m.group(3))/3600
                if m.group(4).upper() == 'S': lat = -lat
                lon = int(m.group(5)) + int(m.group(6))/60 + int(m.group(7))/3600
                if m.group(8).upper() == 'W': lon = -lon
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    norm = f"{lat:.5f},{lon:.5f}"
                    hits.append(LocationHit('coords', norm, 'DMS pattern', 0.9, norm))
            except Exception:
                pass

        # 4) ZIP/Postal (US 5/9)
        for m in re.finditer(r'\b\d{5}(?:-\d{4})?\b', raw):
            if not self.is_in_hashtag_or_social_context(raw, m.start(), m.end()):
                ctx = self._context_snippet(raw, m.start(), m.end())
                hits.append(LocationHit('zip', m.group(0), ctx, 0.7, m.group(0)))

        # 5) Addresses (pyap optional)
        if pyap:
            try:
                for adr in pyap.parse(raw, country='US'):
                    s = str(adr).strip()
                    if not self.is_in_hashtag_or_social_context(raw, getattr(adr, 'start', 0), getattr(adr, 'end', 0)):
                        norm = re.sub(r'\s+', ' ', s).lower()
                        hits.append(LocationHit('address', s, s[:100], 0.85, norm))
            except Exception:
                pass

        # 6) Cities/Countries (geotext optional)
        if GeoText:
            try:
                g = GeoText(raw)
                for city in set(g.cities):
                    start = tl.find(city.lower())
                    if start != -1 and not self.is_in_hashtag_or_social_context(raw, start, start+len(city)):
                        ctx = self._context_snippet(raw, start, start+len(city))
                        hits.append(LocationHit('city', city, ctx, 0.75, city.strip().lower()))
                for country in set(g.countries):
                    start = tl.find(country.lower())
                    if start != -1 and not self.is_in_hashtag_or_social_context(raw, start, start+len(country)):
                        ctx = self._context_snippet(raw, start, start+len(country))
                        hits.append(LocationHit('country', country, ctx, 0.7, country.strip().lower()))
            except Exception:
                pass

        # 7) IATA 3-letter airport tags & location hashtags (#NYC #LosAngeles)
        # Hashtags: keep ONLY if verified as geo; otherwise ignore
        # Flip allow_geocode=True if you want slower but stronger verification
        ALLOW_GEOCODE_FOR_HASHTAGS = False

        for tag in re.findall(r'#([A-Za-z][A-Za-z0-9_-]{2,})', raw):
            t = tag.strip()
            if self._is_geo_hashtag(t, allow_geocode=ALLOW_GEOCODE_FOR_HASHTAGS):
                norm = t.lower()
                hits.append(LocationHit('hashtag_geo', '#'+t, '#'+t, 0.80, norm))


        # 8) Phrases that often leak home/work
        for ph in ('live in', 'based in', 'from ', 'near ', 'at '):
            i = tl.find(ph)
            if i != -1 and not self.is_in_hashtag_or_social_context(raw, i, i+len(ph)):
                ctx = self._context_window(raw, i, len(ph), 40)
                hits.append(LocationHit('phrase', ph, ctx, 0.5, (ph+':'+ctx).lower()))

        # If we found nothing AND it's mostly social/hashtags, bail.
        if not hits and self.is_social_media_content(raw):
            return []

        # Dedupe (keep highest confidence)
        best = {}
        for h in hits:
            key = f"{h.kind}|{h.normalized}"
            if key not in best or h.confidence > best[key].confidence:
                best[key] = h

        final = list(best.values())
        final.sort(key=lambda x: x.confidence, reverse=True)
        return final

    def _context_window(self, text: str, start: int, length: int, window: int) -> str:
        """Get context window around a match"""
        context_start = max(0, start - window)
        context_end = min(len(text), start + length + window)
        return text[context_start:context_end].strip()


    def is_social_media_content(self, text: str) -> bool:
        """Check if text is primarily social media content (hashtags, mentions, URLs, etc.)"""
        if not text:
            return False
        tokens = re.findall(r'#\w+|@\w+|https?://\S+|\w+', text)  # include URLs
        if not tokens:
            return False
        social = [t for t in tokens if t.startswith('#') or t.startswith('@') or t.startswith('http')]
        return (len(social) / len(tokens)) >= 0.6

    def is_in_hashtag_or_social_context(self, text: str, start: int, end: int) -> bool:
        """Check if a match is part of a hashtag or social media context"""
        # Check if it's part of a hashtag
        hashtag_start = text.rfind('#', 0, start)
        if hashtag_start != -1 and hashtag_start < start:
            hashtag_end = text.find(' ', start)
            if hashtag_end == -1:
                hashtag_end = len(text)
            if end <= hashtag_end:
                return True
        
        # Check if it's part of a mention
        mention_start = text.rfind('@', 0, start)
        if mention_start != -1 and mention_start < start:
            mention_end = text.find(' ', start)
            if mention_end == -1:
                mention_end = len(text)
            if end <= mention_end:
                return True
        
        return False



    def _context_snippet(self, text: str, start: int, end: int, window: int = 30) -> str:
        """Get context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        return text[context_start:context_end].strip()

    def _penalty(self, kind: str) -> int:
        return {
            'coords': 20, 'address': 18, 'map_link': 14,
            'city': 10, 'zip': 8, 'country': 8,
            'hashtag_geo': 6,   # verified only
            'phrase': 2         # ↓ less bite for vague phrases
        }.get(kind, 0)


    def get_score_style(self, score):
        """Get CSS style for location privacy score based on value"""
        if score >= 80:
            return "font-size: 18px; font-weight: bold; color: #4CAF50;"  # Green
        elif score >= 60:
            return "font-size: 18px; font-weight: bold; color: #FF9800;"  # Orange
        else:
            return "font-size: 18px; font-weight: bold; color: #F44336;"  # Red

    def _is_geo_hashtag(self, tag: str, allow_geocode: bool = False) -> bool:
        """
        Accept a hashtag as geo ONLY if:
        - GeoText says it's a city/country, OR
        - strict US state name/abbr / ISO country / well-known metro code match, OR
        - (optional) Nominatim forward-geocodes it.
        """
        if not tag:
            return False
        t = tag.strip('#').replace('_',' ').replace('-', ' ').strip()
        if not t:
            return False

        # 1) GeoText (preferred)
        if GeoText:
            try:
                g = GeoText(t)
                if g.cities or g.countries:
                    return True
            except Exception:
                pass

        tl = t.lower()

        # 2) strict namespaces
        US_STATE_ABBR = {
            'al','ak','az','ar','ca','co','ct','de','fl','ga','hi','id','il','in','ia','ks','ky','la',
            'me','md','ma','mi','mn','ms','mo','mt','ne','nv','nh','nj','nm','ny','nc','nd','oh','ok',
            'or','pa','ri','sc','sd','tn','tx','ut','vt','va','wa','wv','wi','wy'
        }
        ISO_COUNTRY_2 = {
            'us','ca','mx','uk','gb','fr','de','it','es','jp','cn','au','br','in','ru'
        }
        METRO_CODES = {'NYC','LA','SF','LAX','JFK','SFO','DFW','DCA','LON','PAR','TYO'}

        # US state abbr or ISO country code (exact)
        if tl in US_STATE_ABBR or tl in ISO_COUNTRY_2:
            return True

        # Common metro codes (all caps)
        if t.isupper() and t in METRO_CODES:
            return True

        # CamelCase “NewYork”, “LosAngeles” → “New York”, check GeoText/geocode
        if re.match(r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$', t):
            parts = re.findall(r'[A-Z][a-z]+', t)
            joined = ' '.join(parts)
            if GeoText:
                try:
                    g = GeoText(joined)
                    if g.cities or g.countries:
                        return True
                except Exception:
                    pass
            if allow_geocode and self._geocode_ok(joined):
                return True

        # Single capitalized word: “London”, “Miami”
        if re.match(r'^[A-Z][a-z]+$', t):
            if GeoText:
                try:
                    g = GeoText(t)
                    if g.cities or g.countries:
                        return True
                except Exception:
                    pass
            if allow_geocode and self._geocode_ok(t):
                return True

        # Fallback: optional geocode on the raw token
        if allow_geocode and self._geocode_ok(t):
            return True

        return False

