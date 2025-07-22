from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from feature_extractor import extract_features_from_url

app = Flask(__name__)
CORS(app)

# --- Load Model ---
print("Loading the FINAL ML model and feature columns...")
try:
    model = joblib.load("phishing_model_final.pkl")
    model_columns = joblib.load("model_columns_final.pkl")
    print("✅ Final model and columns loaded successfully.")
except FileNotFoundError:
    print(
        "🔴 FATAL: Final model files not found. Please run train_final_model.py first!"
    )
    exit()


# In backend/app.py

def generate_evidence_summary(features, result):
    """ Creates a more detailed list of evidence, including explanations. """
    evidence = {"safe_signals": [], "risk_factors": []}
    
    # Define risk checks as tuples: (feature_name, condition, risk_title, explanation)
    risk_checks = [
        ('DomainAge', lambda x: 0 <= x < 180, "Domain is New", "Phishing sites are often hosted on recently created domains."),
        ('InsecureForms', lambda x: x == 1, "Insecure Form", "The page contains login forms that do not use a secure connection."),
        ('IpAddress', lambda x: x == 1, "URL is IP Address", "Legitimate sites rarely use a numeric IP address in the URL."),
        ('DomainInSubdomains', lambda x: x == 1, "Deceptive Subdomain", "The URL may be trying to impersonate a known brand in the subdomain."),
        ('NumSensitiveWords', lambda x: x > 0, "Suspicious Keywords", "The URL contains words commonly associated with phishing (e.g., 'login', 'secure').")
    ]
    
    for feature, condition, title, explanation in risk_checks:
        if condition(features.get(feature, -1)):
            evidence['risk_factors'].append({"risk": title, "explanation": explanation})

    if result == 'safe':
        safe_signals = []
        if features.get('DomainAge', -1) > 730:
            safe_signals.append({"signal": "Well-Established Domain", "explanation": "This domain was registered over two years ago."})
        if features.get('NoHttps') == -1:
            safe_signals.append({"signal": "Secure Connection", "explanation": "The site uses a valid HTTPS connection."})
        if not safe_signals:
            safe_signals.append({"signal": "No Major Risks Detected", "explanation": "Our analysis found no common phishing indicators."})
        evidence['safe_signals'] = safe_signals
            
    return evidence


# --- API Endpoint ---
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        url_to_check = data.get("url")
        if not url_to_check:
            return jsonify({"error": "URL value cannot be empty."}), 400

        url_features = extract_features_from_url(url_to_check)
        features_df = pd.DataFrame([url_features], columns=model_columns)
        prediction = model.predict(features_df)
        result = "phishing" if prediction[0] == 1 else "safe"

        evidence = generate_evidence_summary(url_features, result)

        return jsonify(
            {
                "result": result,
                "url": url_to_check,
                "domain_age": url_features.get("DomainAge", -1),
                "evidence": evidence,
            }
        )
    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
