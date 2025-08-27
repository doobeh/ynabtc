from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, render_template_string
import click
import os
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError
import base64
import email
from datetime import datetime, timezone, date, timedelta
from bs4 import BeautifulSoup
import re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import ynab
from ynab.models.new_transaction import NewTransaction
from ynab.models.post_transactions_wrapper import PostTransactionsWrapper
from dotenv import load_dotenv
from fuzzywuzzy import fuzz, process
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
import secrets

load_dotenv()
app = Flask(__name__)

# Generate a secret key if not provided
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emails.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize OAuth
oauth = OAuth(app)


class Base(DeclarativeBase):
  pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, email, name):
        self.id = email
        self.email = email
        self.name = name

@login_manager.user_loader
def load_user(user_id):
    # In production, you might want to store user info in database
    # For now, we'll create a temporary user object
    return User(user_id, user_id)

def is_allowed_user(email):
    """Check if user email is allowed to access the application"""
    allowed_emails = os.getenv('ALLOWED_EMAILS', '').split(',')
    allowed_emails = [e.strip() for e in allowed_emails if e.strip()]
    
    # If no allowed emails specified, allow any Google account
    if not allowed_emails:
        return True
    
    return email in allowed_emails

# Email model
class Email(db.Model):
    id = db.Column(db.String(255), primary_key=True)  # Gmail message ID
    subject = db.Column(db.String(500))
    date = db.Column(db.String(100))
    amount = db.Column(db.String(50))
    merchant_name = db.Column(db.String(255))
    card_description = db.Column(db.String(255))
    body = db.Column(db.Text)
    status = db.Column(db.String(50), default='processed')  # 'processed' or 'decode_error'
    ynab = db.Column(db.Boolean, default=False)  # True if sent to YNAB
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Email {self.id}: {self.subject}>'

def get_gmail_service():
    """Initialize and return Gmail API service"""
    creds = None
    # Load credentials from token file if it exists
    if os.path.exists(os.path.join(app.instance_path, 'token.json')):
        creds = Credentials.from_authorized_user_file(os.path.join(app.instance_path, 'token.json'))
    
    # If there are no (valid) credentials available, return None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                return None
        else:
            return None
    
    return build('gmail', 'v1', credentials=creds)

def extract_transaction_info(body):
    """Extract transaction information from email body if structured spans exist"""
    try:
        # Try to parse as HTML first
        soup = BeautifulSoup(body, 'html.parser')
        
        # Look for specific spans
        amount_span = soup.find('span', id='amount')
        merchant_span = soup.find('span', id='merchantName')
        card_span = soup.find('span', id='cardDescription')
        
        if amount_span and merchant_span and card_span:
            # If we found all structured elements, return them
            return {
                'amount': amount_span.get_text(strip=True),
                'merchant': merchant_span.get_text(strip=True),
                'card': card_span.get_text(strip=True),
                'structured': True
            }
    except Exception:
        pass
    
    # Return original body if no structured data found
    return {
        'body': body,
        'structured': False
    }


def find_best_payee_match(merchant_name, budget_id):
    """Find the best matching payee from YNAB using fuzzy matching"""
    try:
        configuration = ynab.Configuration(
            access_token=os.getenv("YNAB_ACCESS_TOKEN")
        )
        
        with ynab.ApiClient(configuration) as api_client:
            payees_api = ynab.PayeesApi(api_client)
            payees_response = payees_api.get_payees(budget_id=budget_id)
            payees = payees_response.data.payees
            
            if not payees:
                return None
            
            # Create a list of payee names for matching
            payee_names = [payee.name for payee in payees]
            
            # Try multiple matching strategies
            best_match = None
            best_score = 0
            best_payee = None
            
            # 1. Check for exact substring matches (case insensitive)
            merchant_upper = merchant_name.upper()
            for payee in payees:
                payee_upper = payee.name.upper()
                if payee_upper in merchant_upper or merchant_upper in payee_upper:
                    return payee.name  # Return exact substring match immediately
            
            # 2. Use fuzzy matching with different algorithms
            matching_methods = [
                ('ratio', fuzz.ratio),
                ('partial_ratio', fuzz.partial_ratio),
                ('token_sort_ratio', fuzz.token_sort_ratio),
                ('token_set_ratio', fuzz.token_set_ratio)
            ]
            
            for method_name, method_func in matching_methods:
                for payee in payees:
                    score = method_func(merchant_name.upper(), payee.name.upper())
                    if score > best_score and score >= 75:  # Minimum 75% match
                        best_score = score
                        best_match = method_name
                        best_payee = payee.name
            
            # 3. Use process.extractOne for overall best match
            if not best_payee:
                match_result = process.extractOne(
                    merchant_name, 
                    payee_names, 
                    scorer=fuzz.token_set_ratio
                )
                if match_result and match_result[1] >= 70:  # Lower threshold for process match
                    best_payee = match_result[0]
                    best_score = match_result[1]
            
            return best_payee if best_score >= 70 else None
            
    except Exception as e:
        print(f"Error in payee matching: {str(e)}")
        return None


def send_to_ynab(email_record):
    """Send email transaction to YNAB"""
    if not email_record.amount or not email_record.merchant_name:
        return {"success": False, "error": "Missing amount or merchant name"}
    
    # Check for duplicate transactions in the last 10 minutes
    ten_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
    
    duplicate_check = Email.query.filter(
        Email.merchant_name == email_record.merchant_name,
        Email.amount == email_record.amount,
        Email.ynab == True,  # Already sent to YNAB
        Email.created_at >= ten_minutes_ago,
        Email.id != email_record.id  # Don't match itself
    ).first()
    
    if duplicate_check:
        return {
            "success": False, 
            "error": f"Duplicate transaction detected. Similar transaction (ID: {duplicate_check.id}) was already sent to YNAB within the last 10 minutes."
        }
    
    try:
        configuration = ynab.Configuration(
            access_token=os.getenv("YNAB_ACCESS_TOKEN")
        )
        
        # Clean amount - remove currency symbols and convert to milliunits
        amount_str = email_record.amount.replace('$', '').replace(' USD', '').strip()
        amount_float = float(amount_str)
        amount_milliunits = int(amount_float * 1000) * -1  # Negative for expense
        
        with ynab.ApiClient(configuration) as api_client:
            api_instance = ynab.TransactionsApi(api_client)
            budget_id = os.getenv("YNAB_BUDGET_ID")
            
            # Try to find a better matching payee
            best_payee = find_best_payee_match(email_record.merchant_name, budget_id)
            final_payee_name = best_payee if best_payee else email_record.merchant_name
            
            new_transaction = NewTransaction(
                account_id=os.getenv("YNAB_ACCOUNT_ID"),
                var_date=date.today().isoformat(),
                amount=amount_milliunits,
                memo=f"{email_record.merchant_name}" if best_payee else email_record.merchant_name,
                payee_name=final_payee_name
            )
            
            data = PostTransactionsWrapper(transaction=new_transaction)
            api_response = api_instance.create_transaction(budget_id, data)
            
            # Mark as sent to YNAB
            email_record.ynab = True
            db.session.commit()
            
            return {"success": True, "response": str(api_response)}
            
    except Exception as e:
        return {"success": False, "error": str(e)}


def save_email_to_db(gmail_id, subject, date, email_content, transaction_info):
    """Save email to database if not already exists"""
    existing_email = db.session.get(Email, gmail_id)
    if existing_email:
        return existing_email  # Already exists
    
    # Determine status and extract fields
    if transaction_info['structured']:
        status = 'processed'
        amount = transaction_info.get('amount')
        merchant_name = transaction_info.get('merchant')
        card_description = transaction_info.get('card')
        body = email_content
    else:
        status = 'decode_error'
        amount = None
        merchant_name = None
        card_description = None
        body = transaction_info.get('body', email_content)
    
    # Create new email record
    new_email = Email(
        id=gmail_id,
        subject=subject,
        date=date,
        amount=amount,
        merchant_name=merchant_name,
        card_description=card_description,
        body=body,
        status=status
    )
    
    db.session.add(new_email)
    db.session.commit()
    return new_email

def get_scotiabank_emails():
    """Fetch emails from alerts@scotiabank.com and save to database"""
    service = get_gmail_service()
    if not service:
        return {"error": "Gmail API not authenticated. Please set up credentials."}
    
    try:
        # Search for emails from scotiabank alerts
        query = 'from:alerts@scotiabank.com'
        results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
        messages = results.get('messages', [])
        
        new_emails_count = 0
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            
            # Extract basic info
            headers = msg['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), 'No Date')
            
            # Extract body (prefer HTML for structured data)
            body = ""
            html_body = ""
            
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/html' and 'data' in part['body']:
                        html_body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    elif part['mimeType'] == 'text/plain' and 'data' in part['body']:
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            else:
                if msg['payload']['mimeType'] == 'text/html' and msg['payload']['body'].get('data'):
                    html_body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
                elif msg['payload']['body'].get('data'):
                    body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
            
            # Use HTML body if available, otherwise plain text
            email_content = html_body if html_body else body
            
            # Extract transaction information
            transaction_info = extract_transaction_info(email_content)
            
            # Save to database (only if new)
            email_record = save_email_to_db(message['id'], subject, date, email_content, transaction_info)
            if email_record.created_at.replace(tzinfo=None) >= datetime.now(timezone.utc).replace(second=0, microsecond=0, tzinfo=None):
                new_emails_count += 1
        
        # Return all emails from database
        all_emails = Email.query.order_by(Email.created_at.desc()).all()
        return {"emails": all_emails, "new_count": new_emails_count}
        
    except Exception as e:
        return {"error": f"Error fetching emails: {str(e)}"}

# Authentication routes
@app.route('/login')
def login():
    """Login with Google OAuth"""
    if not app.config.get('GOOGLE_CLIENT_ID') or not app.config.get('GOOGLE_CLIENT_SECRET'):
        return render_template_string("""
            <h1>Google OAuth Not Configured</h1>
            <p>Please add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your .env file</p>
            <p>Get these from <a href="https://console.cloud.google.com/">Google Cloud Console</a></p>
        """), 500
    
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    """Handle Google OAuth callback"""
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if user_info:
            user_email = user_info['email']
            user_name = user_info['name']
            
            # Check if user is allowed
            if not is_allowed_user(user_email):
                return render_template_string("""
                    <h1>Access Denied</h1>
                    <p>Your email {{email}} is not authorized to access this application.</p>
                    <p>Contact the administrator to request access.</p>
                """, email=user_email), 403
            
            # Create user and log them in
            user = User(user_email, user_name)
            login_user(user, remember=True)
            
            return redirect(url_for('emails'))
        else:
            return 'Failed to get user info', 400
            
    except Exception as e:
        return f'Authentication failed: {str(e)}', 400

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Main page - redirect to emails if authenticated, otherwise show login"""
    if current_user.is_authenticated:
        return redirect(url_for('emails'))
    return render_template_string("""
        <h1>YNAB Scotia Integration</h1>
        <p>Monitor Scotia Bank emails and send transactions to YNAB.</p>
        <p><a href="/login">Login with Google</a></p>
    """)

@app.route('/emails')
@login_required
def emails():
    """Display Scotia bank alert emails"""
    result = get_scotiabank_emails()
    if "error" in result:
        return render_template('emails.html', error=result["error"])
    return render_template('emails.html', emails=result["emails"])


@app.route('/send_to_ynab/<email_id>', methods=['POST'])
@login_required
def send_email_to_ynab(email_id):
    """Send a specific email transaction to YNAB"""
    email_record = db.session.get(Email, email_id)
    if not email_record:
        return jsonify({"success": False, "error": "Email not found"}), 404
    
    if email_record.ynab:
        return jsonify({"success": False, "error": "Already sent to YNAB"}), 400
    
    if email_record.status != 'processed':
        return jsonify({"success": False, "error": "Email not properly processed"}), 400
    
    result = send_to_ynab(email_record)
    if result["success"]:
        return jsonify({"success": True, "message": "Transaction sent to YNAB successfully"})
    else:
        return jsonify({"success": False, "error": result["error"]}), 500


@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print("Database tables created successfully!")

@app.cli.command()
def reset_db():
    """Reset the database by dropping and recreating all tables."""
    db.drop_all()
    print("Database tables dropped successfully!")
    db.create_all()
    print("Database tables created successfully!")


@app.cli.command()
def list_budgets():
    """List all YNAB budgets."""
    try:
        configuration = ynab.Configuration(
            access_token=os.getenv("YNAB_ACCESS_TOKEN")
        )
        
        if not configuration.access_token:
            print("Error: YNAB_ACCESS_TOKEN environment variable not set")
            return
        
        with ynab.ApiClient(configuration) as api_client:
            budgets_api = ynab.BudgetsApi(api_client)
            budgets_response = budgets_api.get_budgets()
            budgets = budgets_response.data.budgets
            
            print("\nYNAB Budgets:")
            print("-" * 60)
            for budget in budgets:
                print(f"Name: {budget.name}")
                print(f"ID: {budget.id}")
                print(f"Currency: {budget.currency_format.iso_code}")
                print(f"Last Modified: {budget.last_modified_on}")
                print("-" * 60)
                
    except Exception as e:
        print(f"Error fetching budgets: {str(e)}")


@app.cli.command()
@click.option('--budget-id', help='Budget ID to list accounts for')
def list_accounts(budget_id):
    """List all accounts for a specific budget."""
    try:
        configuration = ynab.Configuration(
            access_token=os.getenv("YNAB_ACCESS_TOKEN")
        )
        
        if not configuration.access_token:
            print("Error: YNAB_ACCESS_TOKEN environment variable not set")
            return
        
        # Use budget_id from environment if not provided
        if not budget_id:
            budget_id = os.getenv("YNAB_BUDGET_ID")
            if not budget_id:
                print("Error: Budget ID not provided and YNAB_BUDGET_ID environment variable not set")
                print("Use: flask list-accounts --budget-id=<budget_id>")
                return
        
        with ynab.ApiClient(configuration) as api_client:
            accounts_api = ynab.AccountsApi(api_client)
            accounts_response = accounts_api.get_accounts(budget_id=budget_id)
            accounts = accounts_response.data.accounts
            
            print(f"\nAccounts for Budget ID: {budget_id}")
            print("-" * 60)
            for account in accounts:
                balance_formatted = f"{account.balance / 1000:.2f}"  # Convert from milliunits
                print(f"Name: {account.name}")
                print(f"ID: {account.id}")
                print(f"Type: {account.type}")
                print(f"Balance: {balance_formatted}")
                print(f"Closed: {account.closed}")
                print("-" * 60)
                
    except Exception as e:
        print(f"Error fetching accounts: {str(e)}")


@app.cli.command()
@click.option('--budget-id', help='Budget ID to list payees for')
def list_payees(budget_id):
    """List all known payees for a specific budget."""
    try:
        configuration = ynab.Configuration(
            access_token=os.getenv("YNAB_ACCESS_TOKEN")
        )
        
        if not configuration.access_token:
            print("Error: YNAB_ACCESS_TOKEN environment variable not set")
            return
        
        # Use budget_id from environment if not provided
        if not budget_id:
            budget_id = os.getenv("YNAB_BUDGET_ID")
            if not budget_id:
                print("Error: Budget ID not provided and YNAB_BUDGET_ID environment variable not set")
                print("Use: flask list-payees --budget-id=<budget_id>")
                return
        
        with ynab.ApiClient(configuration) as api_client:
            payees_api = ynab.PayeesApi(api_client)
            payees_response = payees_api.get_payees(budget_id=budget_id)
            payees = payees_response.data.payees
            
            print(f"\nPayees for Budget ID: {budget_id}")
            print("-" * 60)
            for payee in payees:
                print(f"Name: {payee.name}")
                print(f"ID: {payee.id}")
                print(f"Deleted: {payee.deleted}")
                if hasattr(payee, 'transfer_account_id') and payee.transfer_account_id:
                    print(f"Transfer Account ID: {payee.transfer_account_id}")
                print("-" * 60)
                
    except Exception as e:
        print(f"Error fetching payees: {str(e)}")


@app.cli.command()
@click.option('--budget-id', help='Budget ID to test payee matching against')
def test_payee_matching(budget_id):
    """Test payee matching against current email entries in database."""
    try:
        # Use budget_id from environment if not provided
        if not budget_id:
            budget_id = os.getenv("YNAB_BUDGET_ID")
            if not budget_id:
                print("Error: Budget ID not provided and YNAB_BUDGET_ID environment variable not set")
                print("Use: flask test-payee-matching --budget-id=<budget_id>")
                return
        
        # Get all processed emails from database
        processed_emails = Email.query.filter(Email.status == 'processed').all()
        
        if not processed_emails:
            print("No processed emails found in database.")
            return
        
        print(f"\nTesting Payee Matching for Budget ID: {budget_id}")
        print("=" * 80)
        
        # First, let's get and display all available YNAB payees
        print("\nLoading YNAB payees...")
        try:
            configuration = ynab.Configuration(
                access_token=os.getenv("YNAB_ACCESS_TOKEN")
            )
            
            with ynab.ApiClient(configuration) as api_client:
                payees_api = ynab.PayeesApi(api_client)
                payees_response = payees_api.get_payees(budget_id=budget_id)
                all_payees = payees_response.data.payees

                
                print(f"\nFound {len(all_payees)} total payees, {len(active_payees)} active payees")
                print("\nActive YNAB Payees Available for Matching:")
                print("-" * 50)
                for i, payee in enumerate(all_payees[:20], 1):  # Show first 20
                    print(f"{i:2d}. {payee.name}")
                
                if len(all_payees) > 20:
                    print(f"    ... and {len(all_payees) - 20} more payees")
                
                print("-" * 50)
                
        except Exception as e:
            print(f"Error loading YNAB payees: {str(e)}")
            return
        
        print(f"\nNow testing matching against {len(processed_emails)} email entries...")
        print("=" * 80)
        
        match_count = 0
        no_match_count = 0
        
        for email in processed_emails:
            if not email.merchant_name:
                continue
                
            print(f"\nEmail ID: {email.id}")
            print(f"Original Merchant: {email.merchant_name}")
            print(f"Amount: {email.amount}")
            print(f"Date: {email.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Test payee matching
            matched_payee = find_best_payee_match(email.merchant_name, budget_id)
            
            if matched_payee:
                print(f"✓ MATCH FOUND: {matched_payee}")
                print(f"  → Payee would be: '{matched_payee}'")
                print(f"  → Memo would be: 'Original: {email.merchant_name}'")
                match_count += 1
            else:
                print("✗ NO MATCH FOUND")
                print(f"  → Payee would be: '{email.merchant_name}' (original)")
                print(f"  → Memo would be: '{email.merchant_name}'")
                no_match_count += 1
            
            print("-" * 60)
        
        # Summary
        total_emails = match_count + no_match_count
        match_percentage = (match_count / total_emails * 100) if total_emails > 0 else 0
        
        print(f"\nSUMMARY:")
        print(f"Total processed emails: {total_emails}")
        print(f"Matches found: {match_count} ({match_percentage:.1f}%)")
        print(f"No matches: {no_match_count} ({100-match_percentage:.1f}%)")
        
        if match_count > 0:
            print(f"\n✓ {match_count} transactions would use existing YNAB payees")
        if no_match_count > 0:
            print(f"ℹ {no_match_count} transactions would create new payees in YNAB")
        
    except Exception as e:
        print(f"Error testing payee matching: {str(e)}")


@app.cli.command()
def sync_emails():
    """Sync Scotia Bank emails (for cron jobs)"""
    print(f"[{datetime.now().isoformat()}] Starting email sync...")
    
    try:
        result = get_scotiabank_emails()
        
        if "error" in result:
            print(f"ERROR: {result['error']}")
            exit(1)
        
        total_emails = len(result.get('emails', []))
        new_emails = result.get('new_count', 0)
        
        print(f"SUCCESS: Found {total_emails} total emails, {new_emails} new")
        
        if new_emails > 0:
            print(f"New emails processed: {new_emails}")
        else:
            print("No new emails found")
            
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}")
        exit(1)


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))