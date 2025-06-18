# app.py
# This is the heart of our PhishGuard backend - a simple Flask API.

from flask import Flask, request, jsonify
from flask_cors import CORS  # This lets our browser extension talk to this server.
import joblib
import pandas as pd
from feature_extractor import extract_features_from_url

# --- App Setup ---
app = Flask(__name__)
CORS(app)  # Allow all origins for simplicity in this student project.


print("Loading the FINAL ML model and feature columns...")
try:
    # Point to the new final files
    model = joblib.load('phishing_model_final.pkl')
    model_columns = joblib.load('model_columns_final.pkl')
    print("✅ Final model and columns loaded successfully.")
except FileNotFoundError:
    print("🔴 FATAL: Final model files not found. Please run train_final_model.py first!")
    exit()

# --- API Endpoint ---
@app.route('/analyze', methods=['POST'])
def analyze():
    """ The main endpoint that receives a URL and returns a prediction. """

    # 1. Get the URL from the incoming JSON request.
    try:
        data = request.get_json()
        url_to_check = data['url']
        if not url_to_check:
            raise ValueError("URL cannot be empty.")
    except (TypeError, KeyError, ValueError) as e:
        # If the JSON is badly formatted or the 'url' key is missing.
        return jsonify({"error": f"Invalid request: {e}"}), 400

    # 2. Go get the features for this URL.
    # This calls our other Python file to do the heavy lifting, including the live WHOIS lookup.
    try:
        url_features = extract_features_from_url(url_to_check)
        print(f"DEBUG: Calculated Domain Age for {url_to_check} is: {url_features.get('DomainAge', 'N/A')} days")

    except Exception as e:
        print(f"🔴 Error during feature extraction for {url_to_check}: {e}")
        return jsonify({"error": "Failed to process the URL."}), 500
    

    # 3. Predict!
    # We create a pandas DataFrame, making sure the columns are in the exact
    # order the v2 model was trained on.
    features_df = pd.DataFrame([url_features], columns=model_columns)
    
    prediction = model.predict(features_df)
    result = "phishing" if prediction[0] == 1 else "safe"

    # 4. Send the result back to the Chrome extension.
    return jsonify({
        "result": result,
        "url": url_to_check
    })

    

# This bit just makes the server run when you execute `python3 app.py`
if __name__ == '__main__':
    # NOTE: `debug=True` is great for development as it auto-reloads on changes.
    app.run(host='0.0.0.0', port=5001, debug=True)