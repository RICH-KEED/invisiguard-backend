from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import groq
import json
import re
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

# Initialize Groq client
if not config["api_key"]:
    print("Warning: GROQ_API_KEY not set in environment or config.json. API calls will fail.")
    print(f"Please create a config.json file in the backend directory with this format:")
    print('{"api_key": "your-groq-api-key", "model": "llama3-70b-8192", "temperature": 0.2}')
else:
    groq_client = groq.Client(api_key=config["api_key"])


def extract_domain(url):
    """Extract the domain from a URL"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except:
        return url


def analyze_links(links):
    """Analyze links for suspicious patterns"""
    suspicious_patterns = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'is\.gd', r't\.co',  # URL shorteners
        r'password', r'credential', r'bank', r'urgent', r'verify', r'update',  # Suspicious keywords
        r'\.tk$', r'\.xyz$', r'\.top$', r'\.gq$', r'\.ml$', r'\.ga$', r'\.cf$',  # Suspicious TLDs
        r'0\d{1,2}[a-z]', r'google.*\d+.*\.', r'PayP[a@]l', r'amaz[0o]n'  # Misspelled domains
    ]
    
    suspicious_links = []
    domains = set()
    domain_mismatch = False
    
    for link in links:
        domain = extract_domain(link)
        domains.add(domain)
        
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
    if len(domains) > 2:  # More than 2 different domains can be suspicious
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
    
    # Analyze links if present
    links_analysis = {}
    if 'links' in email_content and email_content['links']:
        links_analysis = analyze_links(email_content['links'])
    
    # Create analysis prompt for the model
    prompt = f"""
    Analyze the following email content for signs of phishing, scams, or fraudulent activity.

    EMAIL DETAILS:
    Subject: {email_content.get('subject', 'Unknown')}
    Sender: {email_content.get('senderName', '')} <{email_content.get('sender', 'Unknown')}>
    
    Body:
    {email_content.get('body', '')}
    
    Links in email: {len(email_content.get('links', []))} links found
    {f"Suspicious links detected: {len(links_analysis.get('suspicious_links', []))}" if links_analysis else ""}
    {f"Multiple different domains detected: {links_analysis.get('domain_mismatch', False)}" if links_analysis else ""}
    
    IMPORTANT GUIDANCE:
    - Be extremely thorough in your analysis
    - Do not assume an email is legitimate just because it appears to be from a well-known company
    - Look for signs of impersonation, urgency, threats, or requests for sensitive information
    - Many scams impersonate legitimate companies like Discord, Microsoft, or banking institutions
    - Look for email address discrepancies (e.g., from Discord but using a gmail address)
    - Examine URLs carefully - legitimate companies rarely use URL shorteners or strange domains
    - Even if email address appears legitimate, the content may still be suspicious

    Provide an assessment categorizing this email as one of the following:
    - "safe" - ONLY if you are VERY CONFIDENT the email is legitimate with no suspicious elements
    - "suspicious" - If there are ANY concerning elements or you're not completely sure
    - "scam" - If the email has clear signs of being a scam or phishing attempt
    
    When in doubt, categorize as "suspicious" rather than "safe".
    
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
            
        # Call Groq API for analysis
        response = groq_client.chat.completions.create(
            model=config["model"],
            messages=[
                {"role": "system", "content": "You are a security expert specialized in detecting email scams and phishing attempts. You are extremely cautious and thorough in your analysis. You know that many scams impersonate legitimate companies, so you never assume an email is safe based solely on the sender's name or domain."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=config["temperature"]
        )
        
        # Parse the model's response
        model_response = response.choices[0].message.content
        analysis = json.loads(model_response)
        
        category = analysis.get("category", "suspicious")
        explanation = analysis.get("explanation", "Could not determine the reason.")
        
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
    return jsonify({
        'status': 'online',
        'configured': has_api_key,
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