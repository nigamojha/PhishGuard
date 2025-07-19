# backend/app.py - FINAL VERSION

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from feature_extractor import extract_features_from_url

# --- App Setup ---
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
    """ Creates a smarter list of reasons based on feature values and the final result. """
    evidence = {
        "safe_signals": [],
        "risk_factors": []
    }
    
    # First, always identify the specific risk factors found.
    if features.get('DomainAge', -1) != -1 and features.get('DomainAge', 999) < 180:
        evidence['risk_factors'].append("Domain is very new")
    if features.get('InsecureForms') == 1:
        evidence['risk_factors'].append("Page contains insecure forms")
    if features.get('IpAddress') == 1:
        evidence['risk_factors'].append("URL is a raw IP address")
    if features.get('DomainInSubdomains') == 1:
        evidence['risk_factors'].append("Brand name used in subdomain")
    if features.get('NumSensitiveWords', 0) > 0:
        evidence['risk_factors'].append("URL contains sensitive keywords")

    # Now, ONLY add safe signals if the final result is "safe".
    if result == 'safe':
        if features.get('DomainAge', -1) > 730: # Over 2 years old
            evidence['safe_signals'].append("Domain is well-established")
        if features.get('NoHttps') == -1:
            evidence['safe_signals'].append("Uses a secure HTTPS connection")
        # If no specific safe signals are found for a safe site, add a general note.
        if not evidence['safe_signals']:
            evidence['safe_signals'].append("No major risks detected")
            
    return evidence

# --- API Endpoint ---
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url_to_check = data.get("url")
        if not url_to_check:
            return jsonify({"error": "URL value cannot be empty."}), 400

        # 1. Extract features
        url_features = extract_features_from_url(url_to_check)
        
        # 2. Create DataFrame
        features_df = pd.DataFrame([url_features], columns=model_columns)
        
        # 3. Make prediction
        prediction = model.predict(features_df)
        result = "phishing" if prediction[0] == 1 else "safe"
        
        # 4. Generate the evidence summary
        evidence = generate_evidence_summary(url_features, result)
        
        # 5. Send the full response back
        return jsonify({
            "result": result,
            "url": url_to_check,
            "domain_age": url_features.get('DomainAge', -1),
            "evidence": evidence
        })

    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)