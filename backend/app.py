# backend/app.py - Simplified Version (No Evidence)

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
        
        # The response is now simpler, without the 'evidence' key
        return jsonify({
            "result": result, 
            "url": url_to_check,
            "domain_age": url_features.get('DomainAge', -1)
        })

    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)