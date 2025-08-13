# TikTok Toolkit - Cybersecurity Analysis Platform

**🚧 WORK IN PROGRESS** - A comprehensive desktop application for TikTok cybersecurity analysis, privacy assessment, and threat detection.

A PySide6 desktop application that provides advanced cybersecurity tools for TikTok content creators, including privacy analysis, bot detection, impersonation monitoring, and stalkerware detection.

## 🎯 Project Status

**Current Progress: 86% Complete (6/7 major features implemented)**

### ✅ **COMPLETED FEATURES:**
- **🔐 Authentication System** - TikTok OAuth 2.0 with PKCE security
- **🛡️ Privacy & Exposure Analysis** - Comprehensive PII detection and geolocation analysis
- **🔍 Video Forensics Dashboard** - Metadata extraction and forensic insights
- **👤 Impersonation Monitor** - Real algorithms for detecting fake accounts
- **📊 Engagement Anomaly Detector** - Statistical analysis for bot detection
- **🕵️ Stalkerware Warning Tool** - Obsessive behavior and interaction pattern analysis

### 🚧 **REMAINING FEATURES:**
- **🌙 Dark UX Detector** - Manipulative engagement pattern detection (14% remaining)

## 🚀 Key Features

### 🔐 **Authentication & Security**
- **Official TikTok OAuth Flow** - Implements TikTok's official authentication
- **PKCE Security** - Uses Proof Key for Code Exchange for enhanced security
- **Token Management** - Automatic token saving and refresh
- **Local Callback Server** - Secure OAuth callback handling

### 🛡️ **Privacy Analysis**
- **PII Detection** - Advanced detection of emails, phones, SSNs, credit cards, URLs, handles, DOBs, postal codes, IPs
- **Geolocation Analysis** - High-precision location extraction with confidence scoring
- **Privacy Scoring** - Deterministic scoring system with clear recommendations
- **Exposure Risk Assessment** - Comprehensive risk analysis and mitigation strategies

### 🔍 **Video Forensics**
- **Metadata Extraction** - Complete video metadata analysis
- **Engagement Statistics** - Comprehensive engagement pattern analysis
- **Forensic Insights** - Professional forensic reporting
- **Data Export** - CSV export capabilities for further analysis

### 👤 **Impersonation Detection**
- **Username Similarity** - Levenshtein distance analysis
- **Bio Similarity** - TF-IDF cosine similarity detection
- **Avatar Analysis** - Perceptual hashing (pHash) for image similarity
- **Profile Cloning Detection** - Advanced pattern recognition

### 📊 **Anomaly Detection**
- **Z-Score Analysis** - Statistical anomaly detection
- **Benford's Law** - Last-digit distribution analysis
- **Rolling MAD** - Temporal spike detection
- **Bot Detection** - Comprehensive bot behavior analysis

### 🕵️ **Stalkerware Detection**
- **Engagement Pattern Analysis** - Obsessive behavior detection
- **Interaction Timing** - Frequency and timing pattern analysis
- **Risk Assessment** - Confidence-based risk scoring
- **Protection Recommendations** - Comprehensive safety guidance

## 📋 Prerequisites

Before using this app, you need to:

1. **Register Your TikTok App**
   - Visit: https://developers.tiktok.com/
   - Create a developer account
   - Register your app
   - Get your Client Key and Client Secret

2. **Configure Redirect URI**
   - Add `http://localhost:8080/callback/` to your app's redirect URIs
   - This must match exactly in your TikTok app configuration

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd tiktok-toolkit
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your TikTok credentials
```

4. **Run the application:**
```bash
python main.py
```

## 🔧 Configuration

Create a `.env` file with your TikTok API credentials:

```env
# TikTok API Credentials (REQUIRED)
CLIENT_KEY=your_client_key_here
CLIENT_SECRET=your_client_secret_here  # REQUIRED for OAuth flow
DEBUG=True
```

**⚠️ IMPORTANT:** The `CLIENT_SECRET` is **REQUIRED** for the OAuth flow to work properly. TikTok's API requires the client secret even for desktop/PKCE applications.

## 🖥️ Application Interface

### 🔐 **Authentication Tab**
- **OAuth Flow** - Secure TikTok authentication
- **Token Management** - View and manage access tokens
- **Status Display** - Real-time authentication status

### 🛡️ **Privacy & Exposure Analysis**
- **General Privacy Analysis** - PII detection and privacy scoring
- **Geolocation Analysis** - Location-based privacy assessment
- **Risk Assessment** - Comprehensive exposure risk analysis

### 🔍 **Video Forensics**
- **Metadata Extraction** - Complete video data analysis
- **Engagement Statistics** - Comprehensive engagement metrics
- **Forensic Reporting** - Professional analysis reports

### 👤 **Impersonation Monitor**
- **Username Analysis** - Similarity detection algorithms
- **Profile Comparison** - Advanced pattern matching
- **Clone Detection** - Fake account identification

### 📊 **Engagement Anomaly Detector**
- **Statistical Analysis** - Z-scores and Benford's Law
- **Bot Detection** - Automated behavior analysis
- **Pattern Recognition** - Anomaly identification

### 🕵️ **Stalkerware Warning Tool**
- **Behavior Analysis** - Obsessive interaction detection
- **Pattern Recognition** - Stalking behavior identification
- **Risk Assessment** - Confidence-based scoring

## 🔍 Technical Capabilities

### **Advanced Algorithms**
- **Levenshtein Distance** - Username similarity analysis
- **TF-IDF Cosine Similarity** - Text similarity detection
- **Perceptual Hashing** - Image similarity analysis
- **Z-Score Analysis** - Statistical anomaly detection
- **Benford's Law** - Numerical pattern analysis
- **Rolling MAD** - Temporal spike detection

### **API Integration**
- **TikTok API v2** - Official API endpoints
- **Pagination Support** - Efficient data retrieval
- **Rate Limiting** - Respectful API usage
- **Error Handling** - Robust error management

### **Data Processing**
- **Unicode Normalization** - Text preprocessing
- **PII Detection** - Comprehensive sensitive data identification
- **Geolocation Extraction** - High-precision location detection
- **Statistical Analysis** - Advanced mathematical modeling

## ⚠️ Important Notes

### **Rate Limits**
- TikTok APIs have rate limits
- The app includes built-in delays between requests
- Respect TikTok's rate limiting guidelines

### **Security**
- Tokens are stored locally in `tiktok_tokens.json`
- Never share your access tokens
- Use HTTPS for production applications
- PII detection includes redaction capabilities

### **Legal Compliance**
- This app uses official TikTok APIs
- Follow TikTok's Terms of Service
- Respect user privacy and data protection laws
- Intended for legitimate cybersecurity analysis

## 🚨 Troubleshooting

### **Common Issues**

1. **"Missing Credentials"**
   - Enter your Client Key and Client Secret in the Authentication tab

2. **"Redirect URI Mismatch"**
   - Ensure `http://localhost:8080/callback/` is registered in your TikTok app

3. **"Port Already in Use"**
   - The app uses port 8080 for the callback server
   - Close other applications using this port

4. **"Authentication Failed"**
   - Check your app configuration in TikTok Developer Portal
   - Verify your redirect URI is correct
   - Ensure your app is approved by TikTok
   - **NEW:** Make sure `CLIENT_SECRET` is set in your `.env` file
   - **NEW:** Check for "invalid_request" errors - these often indicate PKCE or client_secret issues

5. **"Code verifier or code challenge is invalid"**
   - This indicates a PKCE implementation issue (now fixed)
   - Ensure you're using the latest version of the application
   - Clear saved tokens and re-authenticate

6. **"Scope not authorized"**
   - Verify your app has the required scopes: `user.info.basic,user.info.profile,user.info.stats,video.list`
   - Check your app's permissions in the TikTok Developer Portal

### **Debug Mode**

The app includes comprehensive logging. Set `DEBUG=True` in your `.env` file for detailed error messages.

## 📁 Project Structure

```
tiktok-toolkit/
├── main.py                 # Main application entry point
├── app.py                  # Main application class
├── auth_server.py          # OAuth callback server
├── logger.py               # Logging system
├── loading_spinner.py      # UI loading components
├── tabs/                   # Tab components
│   ├── __init__.py
│   ├── main.py            # Authentication tab
│   ├── privacy.py         # Privacy analysis container
│   ├── privacy_general.py # General privacy analysis
│   ├── privacy_geolocation.py # Geolocation analysis
│   ├── forensics.py       # Video forensics
│   ├── impersonation.py   # Impersonation detection
│   ├── anomaly.py         # Anomaly detection
│   └── stalkerware.py     # Stalkerware detection
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
└── README.md              # This file
```

## 🔗 Useful Links

- [TikTok Developer Portal](https://developers.tiktok.com/)
- [Login Kit Documentation](https://developers.tiktok.com/doc/login-kit-desktop)
- [API Documentation](https://developers.tiktok.com/doc/)
- [App Registration Guide](https://developers.tiktok.com/doc/register-app)

## 🤝 Contributing

This is a work in progress. Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚖️ Disclaimer

This application is for **educational and legitimate cybersecurity analysis purposes only**. Users are responsible for complying with TikTok's Terms of Service and applicable laws. The tools provided are intended to help content creators protect their privacy and security on the platform.

## 🚧 Development Status

**Current Version:** 0.9.0 (Beta)
**Last Updated:** January 2025
**Status:** Active Development

This project is actively maintained and new features are being added regularly. The remaining 14% of planned features will be implemented in future updates. 