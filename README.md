# Harmony Security Testing Framework 🛡️

A comprehensive web application security scanning platform built with Flask, OWASP ZAP, and modern web technologies. This framework provides automated vulnerability detection, intelligent risk analysis, and beautiful reporting capabilities for securing web applications.

## ✨ Key Features

### 🔍 Advanced Security Scanning
- **Multi-Mode Scanning**: Light (2-5 min), Medium (8-10 min), and Full (20+ min) scan modes
- **Real-Time Progress Tracking**: Live updates with detailed progress indicators and current scanning rules
- **Intelligent Stop Control**: Properly stop scans at any point with immediate ZAP API integration
- **Browser-Independent**: Headless scanning optimized for containerized environments

### 📊 Smart Risk Analysis
- **AI-Powered Risk Engine**: Automatically prioritizes vulnerabilities based on severity and endpoint criticality
- **Dynamic Risk Scoring**: CWE-based classification with custom risk mappings
- **Critical Endpoint Detection**: Identifies high-value targets like /admin, /login, /api endpoints
- **Confidence Scoring**: ZAP confidence levels integrated into final risk assessment

### 🎯 Professional Dashboard
- **Interactive Charts**: Beautiful Chart.js visualizations with risk distribution analysis
- **Advanced Search & Filtering**: Real-time search across all alerts with multiple filter options
- **Export/Import Capabilities**: CSV export/import for vulnerability data management
- **Responsive Design**: Mobile-friendly interface with Bootstrap 5

### ⏰ Automated Scheduling
- **Flexible Scheduling**: Daily, weekly, and monthly scan automation
- **Background Processing**: APScheduler integration for reliable task execution
- **Schedule Management**: Full CRUD operations for scheduled scans
- **Next Run Predictions**: Intelligent calculation of upcoming scan times

### 🚀 Performance & Reliability
- **Optimized Docker Configuration**: Resource-limited ZAP container with health checks
- **Database Migrations**: Automatic schema updates with backup functionality
- **Error Handling**: Comprehensive exception handling with detailed logging
- **Session Management**: Proper cleanup and session isolation

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Flask Web     │    │   ZAP Scanner   │    │   Risk Engine   │
│   Application   │◄──►│   Container     │◄──►│   Analysis      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SQLite DB     │    │   APScheduler   │    │   Bootstrap UI  │
│   Storage       │    │   Automation    │    │   Frontend      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

- **Backend**: Flask 2.3.3, Python 3.9+
- **Security Engine**: OWASP ZAP (latest stable)
- **Database**: SQLite with automatic migrations
- **Frontend**: Bootstrap 5, Chart.js, jQuery, DataTables
- **Containerization**: Docker & Docker Compose
- **Scheduling**: APScheduler with Cron triggers
- **HTTP Client**: Requests with retry strategies

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM (recommended)
- 10GB+ free disk space

### Installation

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd security-framework
   ```

2. **Start the Application**
   ```bash
   docker-compose up -d
   ```

3. **Access the Dashboard**
   - Web Interface: http://localhost:8080
   - ZAP Proxy: http://localhost:8090

4. **Verify Installation**
   ```bash
   docker-compose ps
   # Should show both 'web' and 'zap' containers as healthy
   ```

### First Scan
1. Navigate to http://localhost:8080
2. Enter a target URL (e.g., https://example.com)
3. Select scan mode (Light recommended for first test)
4. Click "Start Scan" and watch real-time progress
5. View results in the dashboard when complete

## 📋 Detailed Usage

### Scan Modes

| Mode   | Duration | Depth | Use Case |
|--------|----------|-------|----------|
| Light  | 2-5 min  | 1 level | Quick security checks, CI/CD integration |
| Medium | 8-10 min | 2 levels | Regular security assessments |
| Full   | 20+ min  | 3+ levels | Comprehensive security audits |

### Scheduling Scans

1. **Navigate to Schedule Page**
   - Click "Schedule Scans" in the navigation

2. **Create New Schedule**
   ```
   Target URL: https://your-app.com
   Schedule Type: Daily/Weekly/Monthly
   Time: 02:00 AM (recommended for low traffic)
   Description: Production security scan
   ```

3. **Manage Schedules**
   - Toggle active/inactive status
   - View next run times
   - Delete obsolete schedules

### API Endpoints

#### Scan Management
```bash
# Start a scan
POST /start_scan
Content-Type: application/x-www-form-urlencoded
target_url=https://example.com&scan_mode=light

# Check scan status
GET /scan_status/{scan_id}

# Stop a running scan
POST /stop_scan/{scan_id}
```

#### Data Access
```bash
# Get all alerts
GET /api/alerts

# Search alerts
GET /api/alerts/search?q=xss&risk_level=High

# Get scan statistics
GET /api/statistics

# Export alerts to CSV
GET /export_alerts
```

## 🔧 Configuration

### Environment Variables

```bash
# Database configuration
DB_PATH=/data/scan_results.db

# ZAP configuration
ZAP_HOST=zap
ZAP_PORT=8080
ZAP_API_KEY=zap-api-key-12345

# Docker configuration
DOCKER_CLIENT_TIMEOUT=300
COMPOSE_HTTP_TIMEOUT=300
```

### ZAP Scanner Configuration

The framework automatically configures ZAP for optimal performance:

```yaml
# docker-compose.yml ZAP configuration
- config scanner.threadPerHost=1
- config scanner.delayInMs=200
- config spider.maxDepth=1
- config scanner.domxss.enabled=false
- config scanner.ajaxSpider.enabled=false
```

### Database Schema

```sql
-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target_url TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    total_alerts INTEGER,
    high_risk INTEGER,
    medium_risk INTEGER,
    low_risk INTEGER,
    info_risk INTEGER,
    status TEXT DEFAULT 'Completed',
    duration INTEGER DEFAULT 0,
    scan_type TEXT DEFAULT 'Full',
    progress INTEGER DEFAULT 0
);

-- Alerts table
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    alert_name TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    url TEXT NOT NULL,
    cwe_id TEXT,
    description TEXT,
    is_critical_endpoint INTEGER,
    confidence TEXT,
    scan_date TEXT,
    scan_id INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

-- Scheduled scans table
CREATE TABLE scheduled_scans (
    id INTEGER PRIMARY KEY,
    target_url TEXT NOT NULL,
    schedule_type TEXT NOT NULL,
    schedule_time TEXT NOT NULL,
    schedule_day TEXT,
    next_scan_date TEXT,
    last_scan_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    is_active INTEGER DEFAULT 1,
    description TEXT
);
```

## 🐳 Docker Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   # Create data directory
   mkdir -p ./data
   chmod 755 ./data
   
   # Set production environment variables
   export DB_PATH=/data/scan_results.db
   export DOCKER_CLIENT_TIMEOUT=600
   ```

2. **Start Services**
   ```bash
   docker-compose -f docker-compose.yml up -d
   ```

3. **Monitor Health**
   ```bash
   docker-compose logs -f web
   docker-compose logs -f zap
   ```

### AWS EC2 Deployment

1. **Launch EC2 Instance**
   - Instance Type: t3.medium (4GB RAM minimum)
   - Security Group: Allow ports 22, 80, 8080
   - Storage: 20GB+ EBS volume

2. **Install Dependencies**
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   
   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

3. **Deploy Application**
   ```bash
   git clone <repository-url>
   cd security-framework
   docker-compose up -d
   ```

4. **Configure Reverse Proxy (Optional)**
   ```nginx
   # /etc/nginx/sites-available/security-scanner
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## 📈 Performance Optimization

### Resource Tuning

```yaml
# docker-compose.yml optimizations
services:
  zap:
    environment:
      - JAVA_OPTS=-Xmx512m -XX:+UseG1GC -XX:+UseZGC
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

### Scan Performance Tips

1. **Use Light Mode for CI/CD**: 2-5 minute scans perfect for automated testing
2. **Schedule Heavy Scans**: Run full scans during off-peak hours
3. **Monitor Resources**: Keep ZAP memory usage under 512MB
4. **Clean Database**: Regularly archive old scan results

## 🔒 Security Considerations

### Access Control
- **API Key Protection**: ZAP API key is configured in docker-compose
- **Network Isolation**: ZAP container runs in isolated bridge network
- **File Permissions**: Database files have restricted access

### Scan Ethics
⚠️ **Important**: Always obtain proper authorization before scanning any website

- Only scan websites you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Be aware of potential service disruption
- Follow responsible disclosure for findings

### Data Protection
- Scan results may contain sensitive information
- Implement proper backup and retention policies
- Consider encryption for sensitive deployment environments

## 🛠️ Development

### Local Development Setup

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd security-framework
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Database Migration**
   ```bash
   python migrate_db.py
   ```

3. **Run Development Server**
   ```bash
   python app.py
   ```

### Project Structure

```
security-framework/
├── app.py                 # Main Flask application
├── zap_scanner.py         # ZAP integration and scanning logic
├── risk_engine.py         # Vulnerability analysis and prioritization
├── migrate_db.py          # Database schema migrations
├── docker-compose.yml     # Container orchestration
├── Dockerfile            # Web application container
├── requirements.txt      # Python dependencies
├── templates/            # Jinja2 HTML templates
│   ├── base.html         # Base template with navigation
│   ├── home.html         # Main dashboard
│   ├── dashboard.html    # Alerts management
│   ├── schedule.html     # Scan scheduling
│   └── scan_details.html # Individual scan results
└── data/                 # Persistent data storage
    └── scan_results.db   # SQLite database
```

### Contributing

1. **Fork the Repository**
2. **Create Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make Changes**
4. **Test Thoroughly**
5. **Submit Pull Request**

## 📊 Monitoring & Troubleshooting

### Health Checks

```bash
# Check application health
curl http://localhost:8080/api/statistics

# Check ZAP health
curl http://localhost:8090/JSON/core/view/version/?apikey=zap-api-key-12345

# Check container status
docker-compose ps
```

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| ZAP Not Ready | Scan fails to start | Wait 60-90s for ZAP startup, check logs |
| Memory Issues | Container restarts | Increase memory limits in docker-compose.yml |
| Permission Errors | Database write failures | Check file permissions on data directory |
| Scan Timeouts | Long-running scans fail | Adjust timeout values in ZAP configuration |

### Log Analysis

```bash
# View application logs
docker-compose logs -f web

# View ZAP logs
docker-compose logs -f zap

# Check scan history
tail -f security_scanner.log
```

## 📚 API Reference

### Scan Operations

#### POST /start_scan
Start a new security scan
```javascript
// Request
{
    "target_url": "https://example.com",
    "scan_mode": "light"  // light|medium|full
}

// Response
{
    "scan_id": "uuid-string",
    "scan_mode": "light"
}
```

#### GET /scan_status/{scan_id}
Get scan progress and status
```javascript
// Response
{
    "target_url": "https://example.com",
    "status": "Running active scan",
    "progress": 65,
    "completed": false,
    "scan_db_id": 123
}
```

#### POST /stop_scan/{scan_id}
Stop a running scan
```javascript
// Response
{
    "success": true,
    "message": "Scan stopped successfully",
    "scan_id": "uuid-string"
}
```

### Data Access

#### GET /api/alerts
Retrieve all security alerts
```javascript
// Response
[
    {
        "id": 1,
        "alert_name": "SQL Injection",
        "risk_level": "High",
        "url": "https://example.com/login",
        "cwe_id": "89",
        "description": "SQL injection vulnerability detected",
        "confidence": "High",
        "scan_date": "2025-08-31T10:30:00"
    }
]
```

#### GET /api/alerts/search
Search and filter alerts
```javascript
// Query parameters
?q=sql&risk_level=High&limit=50

// Response - same format as /api/alerts
```

#### GET /api/statistics
Get dashboard statistics
```javascript
// Response
{
    "total_scans": 45,
    "total_alerts": 128,
    "high_risk_alerts": 12,
    "recent_scans": 8,
    "risk_distribution": [
        {"risk_level": "High", "count": 12},
        {"risk_level": "Medium", "count": 34}
    ]
}
```

## 🎯 Use Cases

### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Security Scan
        run: |
          curl -X POST http://scanner.company.com/start_scan \
            -d "target_url=https://staging.app.com&scan_mode=light"
```

### Regular Security Audits
- Schedule weekly scans for production applications
- Configure alerts for high-risk vulnerabilities
- Generate monthly security reports

### Penetration Testing
- Use full scan mode for comprehensive testing
- Export results for penetration testing reports
- Track vulnerability remediation over time

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Support

### Community
- 📧 Email: security-team@company.com
- 💬 Discord: [Security Community](https://discord.gg/security)
- 📖 Documentation: [Wiki](https://github.com/company/security-framework/wiki)

### Professional Support
- 🔧 Professional consulting available
- 🎓 Training and workshops
- 🏢 Enterprise support packages

## 🎉 Acknowledgments

- **OWASP ZAP Team** - For the amazing security scanning engine
- **Flask Community** - For the robust web framework
- **Bootstrap Team** - For the beautiful UI components
- **Chart.js** - For the interactive visualizations

---

**Made with ❤️ by the Security Team**

*Securing the web, one scan at a time* 🛡️

> ⚠️ **Ethical Use Only**: This tool is designed for authorized security testing. Always obtain proper permission before scanning any website or application.
