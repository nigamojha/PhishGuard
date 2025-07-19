

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
    model = joblib.load('phishing_model_final.pkl')
    model_columns = joblib.load('model_columns_final.pkl')
    print("✅ Final model and columns loaded successfully.")
except FileNotFoundError:
    print("🔴 FATAL: Final model files not found. Please run train_final_model.py first!")
    exit()

# --- Smarter Evidence Generation Logic ---
def generate_evidence_summary(features, result):
    evidence = {"safe_signals": [], "risk_factors": []}
    
    # Define risk checks as a list of tuples: (feature_name, condition, message)
    risk_checks = [
        ('DomainAge', lambda x: x != -1 and x < 180, "Domain is very new"),
        ('InsecureForms', lambda x: x == 1, "Page contains insecure forms"),
        ('IpAddress', lambda x: x == 1, "URL uses a numeric IP address"),
        ('DomainInSubdomains', lambda x: x == 1, "Deceptive brand name in subdomain"),
        ('NumSensitiveWords', lambda x: x > 0, "URL contains sensitive keywords")
    ]
    
    for feature, condition, message in risk_checks:
        if condition(features.get(feature, 0)):
            evidence['risk_factors'].append(message)

    # Only add safe signals if the final result is "safe"
    if result == 'safe':
        if features.get('DomainAge', -1) > 730:
            evidence['safe_signals'].append("Domain is well-established")
        if features.get('NoHttps') == -1:
            evidence['safe_signals'].append("Uses a secure HTTPS connection")
        if not evidence['safe_signals']:
            evidence['safe_signals'].append("No major risks detected")
            
    return evidence

# --- API Endpoint ---
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url_to_check = data.get("url")
        if not url_to_check: return jsonify({"error": "URL value cannot be empty."}), 400

        url_features = extract_features_from_url(url_to_check)
        features_df = pd.DataFrame([url_features], columns=model_columns)
        prediction = model.predict(features_df)
        result = "phishing" if prediction[0] == 1 else "safe"
        
        evidence = generate_evidence_summary(url_features, result)
        
        return jsonify({
            "result": result, "url": url_to_check,
            "domain_age": url_features.get('DomainAge', -1), "evidence": evidence
        })
    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)