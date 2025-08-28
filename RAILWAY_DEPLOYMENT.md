# Railway Deployment Guide

This guide covers deploying your YNAB Scotia Integration application on Railway with persistent storage and Gmail authentication.

## Environment Variables Required

Set these in Railway's environment variables section:

### **Required for Production:**
```bash
# Gmail Authentication (for email polling)
RAILWAY_VOLUME_MOUNT_PATH=/data

# Google OAuth (for web login)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# YNAB Integration
YNAB_ACCESS_TOKEN=your_ynab_token
YNAB_BUDGET_ID=your_budget_id
YNAB_ACCOUNT_ID=your_account_id

# Security
SECRET_KEY=your_random_secret_key_here
```

### **Optional:**
```bash
# Restrict web access to specific emails
ALLOWED_EMAILS=admin@company.com,user@domain.com

# Custom port (Railway sets this automatically)
PORT=5000
```

## Persistent Volume Setup

### **1. Create Railway Volume**
- Go to your Railway project
- Click "Variables" tab
- Add a "Volume" 
- Set mount path: `/data`
- Size: 1GB (sufficient for SQLite database)

### **2. Files Stored in Persistent Volume**
Your volume will contain:
- `/data/emails.db` - SQLite database
- `/data/token.json` - Gmail API refresh token
- `/data/credentials.json` - Gmail API credentials

## Gmail API Setup

### **1. Google Cloud Console Setup**
1. Create project at [Google Cloud Console](https://console.cloud.google.com/)
2. Enable Gmail API
3. Create OAuth2 credentials (Desktop Application type)
4. Download `credentials.json`

### **2. Initial Authentication Setup**
Since Railway doesn't have a browser for OAuth, you need to set up authentication locally first:

```bash
# Run locally to create token.json
uv run python setup_gmail.py
```

This creates `instance/token.json` which you'll upload to Railway.

### **3. Upload Credentials to Railway**

**Option A: Railway CLI**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Upload files to volume
railway run --mount /data bash -c "mkdir -p /data"
# Copy your local files
scp instance/credentials.json user@railway:/data/
scp instance/token.json user@railway:/data/
```

**Option B: Environment Variables (Less Secure)**
Convert files to base64 and set as environment variables:
```bash
# Convert to base64
base64 instance/credentials.json > credentials.b64
base64 instance/token.json > token.b64

# Set environment variables in Railway
GMAIL_CREDENTIALS_B64=<content of credentials.b64>
GMAIL_TOKEN_B64=<content of token.b64>
```

Then decode in startup script.

## Health Monitoring

Railway will monitor these endpoints:

### **Health Check:** `/health`
Returns system status:
```json
{
  "status": "healthy",
  "database": "ok", 
  "gmail_auth": "ok",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Auth Status:** `/auth/status` (requires login)
Detailed Gmail authentication status

## Cron Job Setup

Set up email syncing with Railway's cron service or external service:

### **Railway Native (if available):**
```yaml
# railway.toml
[build]
  builder = "nixpacks"

[deploy]
  healthcheckPath = "/health"
  
[[services]]
  name = "email-sync"
  schedule = "*/5 * * * *"  # Every 5 minutes
  command = "flask --app main sync-emails"
```

### **External Cron (Recommended):**
Use GitHub Actions, Zapier, or similar:

```yaml
# .github/workflows/sync-emails.yml
name: Sync Emails
on:
  schedule:
    - cron: '*/5 * * * *'  # Every 5 minutes
jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger email sync
        run: |
          curl -X POST https://your-app.railway.app/webhook/sync-emails
```

## Security Considerations

### **Token Refresh Handling**
- Gmail tokens auto-refresh when expired
- Failed refreshes are logged with timestamps
- Health check monitors authentication status

### **Access Control**
- Web interface protected by Google OAuth
- CLI commands don't require authentication
- Environment variables secure sensitive data

### **Monitoring**
```bash
# Check health
curl https://your-app.railway.app/health

# View logs
railway logs --follow
```

## Troubleshooting

### **Gmail Token Expired**
```bash
# Check auth status (requires web login)
curl https://your-app.railway.app/auth/status

# Re-create token locally and upload
python setup_gmail.py
# Upload new token.json to Railway volume
```

### **Database Issues**
```bash
# Reset database (destructive!)
railway run flask --app main reset-db

# Check database
railway run flask --app main list-budgets
```

### **Volume Mount Issues**
- Ensure `RAILWAY_VOLUME_MOUNT_PATH=/data` is set
- Check volume is properly mounted in Railway dashboard
- Files should persist between deployments

## Local Development

For local development:
```bash
# Use local instance directory
unset RAILWAY_VOLUME_MOUNT_PATH

# Run locally
uv run python main.py

# Access at http://localhost:5000
```

## Production Checklist

- ✅ Railway volume created and mounted at `/data`
- ✅ All environment variables set
- ✅ Gmail credentials uploaded to volume
- ✅ Google OAuth redirect URI configured
- ✅ YNAB credentials tested
- ✅ Health check endpoint responding
- ✅ Email sync scheduled
- ✅ Web access restricted (if needed)

Your application is now production-ready with persistent storage and robust error handling!