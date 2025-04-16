from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import re
import requests
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes to allow the extension to make requests

# Configuration
# You can set your Groq API key in a config.json file or as an environment variable
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

def load_config():
    """Load configuration from config.json file or environment variables"""
    config = {
        "api_key": os.environ.get("GROQ_API_KEY", ""),
        "model": os.environ.get("GROQ_MODEL", "llama3-70b-8192"),
        "temperature": float(os.environ.get("GROQ_TEMPERATURE", "0.2"))
    }
    
    # Try to load from config file if it exists
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"Error loading config file: {str(e)}")
    
    return config

config = load_config()

# Known legitimate email senders and their common email patterns
LEGITIMATE_SENDER_PATTERNS = [
    (r'discord', r'(discord\.com|discordapp\.com)'),
    (r'google', r'(google\.com|gmail\.com|accounts\.google\.com)'),
    (r'microsoft', r'(microsoft\.com|outlook\.com|live\.com)'),
    (r'amazon', r'(amazon\.com|aws\.amazon\.com)'),
    (r'apple', r'(apple\.com|icloud\.com)'),
    (r'render', r'render\.com'),
    (r'github', r'github\.com'),
    (r'facebook', r'(facebook\.com|fb\.com|meta\.com)'),
    (r'twitter', r'twitter\.com'),
    (r'linkedin', r'linkedin\.com')
]

# Explicitly known legitimate sender addresses for security and system notifications
KNOWN_SECURITY_SENDERS = [
    "no-reply@accounts.google.com",
    "security-noreply@linkedin.com",
    "noreply@github.com",
    "security@microsoft.com",
    "account-security-noreply@accountprotection.microsoft.com",
    "no-reply@dropboxmail.com",
    "no-reply@notify.microsoft.com",
    "apple@email.apple.com"
]

# Explicitly recognize common safe security-related email subjects
SECURITY_ALERT_SUBJECTS = [
    "security alert",
    "sign-in attempt",
    "new sign-in",
    "new device",
    "verify your",
    "password reset",
    "authentication",
    "two-factor",
    "2fa",
    "security notification",
    "security code",
    "account access",
    "verification code"
]

# Define direct Groq API function without using the library
def call_groq_api(prompt, system_message="You are a security expert specialized in detecting email scams and phishing attempts."):
    """Call Groq API directly using requests instead of the groq library"""
    if not config["api_key"]:
        raise ValueError("Groq API key not configured")
    
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": config["temperature"]
    }
    
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=data
    )
    
    if response.status_code != 200:
        raise Exception(f"API request failed with status code {response.status_code}: {response.text}")
    
    result = response.json()
    return result["choices"][0]["message"]["content"]


def extract_domain(url):
    """Extract the domain from a URL"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except:
        return url


def is_likely_legitimate(sender, subject, links):
    """Pre-check if an email is likely to be legitimate based on known patterns"""
    if not sender:
        return False, "No sender information available"
    
    # Check if this is a known security alert sender
    if sender.lower() in [s.lower() for s in KNOWN_SECURITY_SENDERS]:
        subject_lower = subject.lower()
        
        # Check if subject looks like a security alert
        for security_subject in SECURITY_ALERT_SUBJECTS:
            if security_subject in subject_lower:
                return True, f"This appears to be a legitimate security alert from {sender}"
        
        # Even without matching subject, known security senders are typically legitimate
        return True, f"This appears to be a legitimate notification from {sender}"
    
    # Extract domain from sender email
    if '@' in sender:
        sender_domain = sender.split('@')[1].lower()
        
        # Check if this appears to be a legitimate company email
        matched_company = None
        is_domain_match = False
        
        for company, domain_pattern in LEGITIMATE_SENDER_PATTERNS:
            if re.search(domain_pattern, sender_domain, re.IGNORECASE):
                matched_company = company
                is_domain_match = True
                break
        
        # If we found a potential company match, check for common legitimate email patterns
        if matched_company:
            # If it's from Google and includes "security" or "alert" in the subject, likely legitimate
            if matched_company == "google" and any(term in subject.lower() for term in ["security", "alert", "verify", "sign-in"]):
                return True, f"Email appears to be a legitimate security notification from Google"
                
            # Check links to see if they match the sender's domain
            if links:
                link_domains = [extract_domain(link) for link in links]
                matching_domains = 0
                
                for domain in link_domains:
                    if re.search(domain_pattern, domain, re.IGNORECASE):
                        matching_domains += 1
                
                # If most links match the sender domain, it's more likely legitimate
                if matching_domains / len(links) >= 0.6:  # Lowered threshold to 60% matching
                    return True, f"Email appears to be from {matched_company} with matching links"
    
    # Look for common legitimate email subjects
    common_legitimate_patterns = [
        r'(welcome|confirm|verify|subscription|newsletter|receipt|invoice|order|shipping|delivery|account|update|security|privacy|terms|policy)',
        r'(password reset|login|sign-in|2fa|two-factor|authentication)',
        r'(notification|reminder|alert|news|announcement|payment|billing)'
    ]
    
    subject_matches = 0
    for pattern in common_legitimate_patterns:
        if re.search(pattern, subject, re.IGNORECASE):
            subject_matches += 1
    
    # If domain matches and subject contains common legitimate patterns
    if is_domain_match and subject_matches > 0:
        return True, f"Email appears to be a legitimate communication from {matched_company}"
    
    return False, "Needs further analysis"


def analyze_links(links):
    """Analyze links for suspicious patterns"""
    suspicious_patterns = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'is\.gd', r't\.co',  # URL shorteners
        r'credential', r'bank', r'urgent', r'verify-now', r'limited-time',  # Suspicious keywords - removed "password", "verify", "update" as these are too common in legitimate emails
        r'\.tk$', r'\.xyz$', r'\.top$', r'\.gq$', r'\.ml$', r'\.ga$', r'\.cf$',  # Suspicious TLDs
        r'0\d{1,2}[a-z]', r'google.*\d+.*\.', r'PayP[a@]l', r'amaz[0o]n'  # Misspelled domains
    ]
    
    suspicious_links = []
    domains = set()
    domain_mismatch = False
    
    for link in links:
        domain = extract_domain(link)
        domains.add(domain)
        
        # Skip links to very common legitimate domains
        if any(common in domain.lower() for common in ["google.com", "microsoft.com", "apple.com", "amazon.com", "youtube.com"]):
            continue
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if re.search(pattern, link, re.IGNORECASE):
                suspicious_links.append({
                    "link": link,
                    "domain": domain,
                    "pattern": pattern
                })
                break
    
    # Look for domain inconsistency (multiple different domains)
    if len(domains) > 3:  # More than 3 different domains can be suspicious
        domain_mismatch = True
    
    return {
        "total_links": len(links),
        "unique_domains": len(domains),
        "suspicious_links": suspicious_links,
        "domain_mismatch": domain_mismatch
    }


@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.json
    if not data or 'content' not in data:
        return jsonify({'error': 'No content provided'}), 400
    
    email_content = data['content']
    
    sender = email_content.get('sender', '')
    subject = email_content.get('subject', '')
    
    # Special case for Google security alerts
    if sender.lower() == "no-reply@accounts.google.com" and "security" in subject.lower():
        return jsonify({
            'result': 'safe',
            'reason': "This is a legitimate security alert from Google. These alerts are sent from no-reply@accounts.google.com and are standard notifications about your account security."
        })
    
    # First, do a quick check to see if this is likely a legitimate email
    likely_legitimate, reason = False, ""
    likely_legitimate, reason = is_likely_legitimate(sender, subject, email_content.get('links', []))
    
    # Analyze links if present
    links_analysis = {}
    if 'links' in email_content and email_content['links']:
        links_analysis = analyze_links(email_content['links'])
    
    # Create analysis prompt for the model with better guidance
    prompt = f"""
    Analyze the following email content for signs of phishing, scams, or fraudulent activity.

    EMAIL DETAILS:
    Subject: {email_content.get('subject', 'Unknown')}
    Sender: {email_content.get('senderName', '')} <{email_content.get('sender', 'Unknown')}>

    Body:
    {email_content.get('body', '')}

    Links in email: {len(email_content.get('links', []))} links found
    {f"Suspicious links detected: {len(links_analysis.get('suspicious_links', []))}" if links_analysis else ""}

    PRELIMINARY ANALYSIS:
    {f"This email appears to be legitimate: {reason}" if likely_legitimate else "This email needs careful analysis."}

    IMPORTANT GUIDANCE:
    - Security alerts from Google (no-reply@accounts.google.com) are standard legitimate notifications
    - Many legitimate emails from companies like Google, Microsoft, Discord, etc. will include multiple links
    - Standard informational or transactional emails from known companies are usually safe
    - Common legitimate emails include: welcome messages, account updates, newsletters, receipts, order confirmations
    - Security alerts, login verification, password resets, and feature announcements from known companies are typically legitimate
    - Policy updates and terms of service notifications are routine business communications

    However, be alert for:
    - Emails that create a sense of urgency about account suspension or security threats
    - Requests for personal information, passwords, or financial details
    - Obvious grammar or spelling errors in professional communications
    - Demands for immediate action to avoid negative consequences
    - Mismatched sender email addresses (e.g., Google notification from a non-Google domain)

    Provide an assessment categorizing this email as one of the following:
    - "safe" - The email appears to be a legitimate business communication with no suspicious elements
    - "suspicious" - The email has concerning elements that warrant caution
    - "scam" - The email is clearly attempting to scam, phish, or defraud the recipient

    Provide a brief explanation (1-3 sentences) for your assessment.

    Return your response in this JSON format:
    {{
        "category": "safe/suspicious/scam",
        "explanation": "Your brief explanation here"
    }}
    """
    
    try:
        if not config["api_key"]:
            return jsonify({
                'result': 'error',
                'reason': 'Groq API key not configured. Please set up your API key in the backend.'
            }), 500
            
        # Call Groq API directly with an improved system message
        system_message = """
        You are a balanced email security analyzer who can identify both legitimate and fraudulent emails accurately.
        
        VERY IMPORTANT GUIDELINES:
        1. LEGITIMATE SECURITY EMAILS: Security alerts and notifications from major companies like Google (no-reply@accounts.google.com), Microsoft, Apple, etc. are normal and legitimate. These often contain links and discuss security concerns.
        
        2. DEFAULT TO TRUST FOR MAJOR SERVICES: Emails from known services with matching domains are usually legitimate. When uncertain but the email is from a major service (Google, Discord, Microsoft, etc.) with a verified sender domain, prefer marking as SAFE.
        
        3. SUSPICIOUS SIGNALS:
        - Urgency and threats that demand immediate action
        - Poor grammar in supposedly professional communications
        - Direct requests for passwords or financial details
        - Sender domains that don't match the claimed identity
        
        4. SECURITY NOTIFICATION CONTEXT: Many legitimate emails mention password reset, account verification, security alerts, etc. These are normal for legitimate service providers and should not alone trigger "suspicious" flags.
        
        5. CLASSIFICATION THRESHOLDS:
        - "safe" - Default for emails from known senders unless clear red flags exist
        - "suspicious" - Only use when concrete suspicious elements exist, not for routine business emails
        - "scam" - Clear evidence of fraudulent intent
        
        DON'T BE OVERLY CAUTIOUS - most emails from legitimate services are safe, even when discussing security topics or containing multiple links.
        """
        
        try:
            model_response = call_groq_api(prompt, system_message)
            analysis = json.loads(model_response)
            
            category = analysis.get("category", "suspicious")
            explanation = analysis.get("explanation", "Could not determine the reason.")
            
            # Special case for security alerts from Google and other known services
            if sender.lower() in [s.lower() for s in KNOWN_SECURITY_SENDERS]:
                if category != "scam":  # If not clearly a scam
                    category = "safe"
                    explanation = f"This appears to be a legitimate security notification from {sender}. {explanation}"
            
            # If our preliminary check deemed it legitimate, and the model is uncertain or borderline,
            # lean toward marking it as safe
            elif likely_legitimate and category == "suspicious" and not any(term in explanation.lower() for term in ["urgent", "sensitive", "request", "password", "personal information"]):
                category = "safe"
                explanation = f"{explanation} However, this appears to be a routine communication from a recognized sender."
            
            # Map category to our result types
            result_type = {
                "safe": "safe",
                "suspicious": "suspicious", 
                "scam": "scam"
            }.get(category, "suspicious")
            
            return jsonify({
                'result': result_type,
                'reason': explanation
            })
        except Exception as api_error:
            print(f"API Error: {str(api_error)}")
            return jsonify({
                'result': 'error',
                'reason': f"Error calling Groq API: {str(api_error)}"
            }), 500
    
    except Exception as e:
        print(f"Error analyzing email: {str(e)}")
        return jsonify({
            'result': 'error',
            'reason': f"An error occurred during analysis: {str(e)}"
        }), 500


@app.route('/check-connection', methods=['GET'])
def check_connection():
    """Endpoint to check if the backend is running and properly configured"""
    has_api_key = bool(config["api_key"])
    
    if has_api_key:
        # Test the API connection
        try:
            response = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {config['api_key']}"}
            )
            api_accessible = response.status_code == 200
        except:
            api_accessible = False
    else:
        api_accessible = False
    
    return jsonify({
        'status': 'online',
        'configured': has_api_key,
        'api_accessible': api_accessible,
        'model': config["model"] if has_api_key else None
    })


@app.route('/', methods=['GET'])
def index():
    """Simple index route to confirm the API is running"""
    return jsonify({
        'status': 'online',
        'name': 'InvisiGuard Backend API',
        'description': 'Email phishing detection API powered by Groq AI'
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    
    print(f"InvisiGuard backend starting...")
    print(f"Using Groq model: {config['model']}")
    print(f"API Key configured: {'Yes' if config['api_key'] else 'No - Please set up your API key'}")
    print(f"Server running at http://localhost:{port}")
    
    app.run(debug=debug, host='0.0.0.0', port=port)
