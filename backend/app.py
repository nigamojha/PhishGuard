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
# In backend/app.py

@app.route('/analyze', methods=['POST'])
def analyze():
    """ Receives a URL, extracts features, predicts, and returns the result with DomainAge. """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request: JSON with 'url' key is required."}), 400

        url_to_check = data.get("url")
        if not url_to_check:
            return jsonify({"error": "URL value cannot be empty."}), 400

        # 1. Extract all features, including DomainAge
        url_features = extract_features_from_url(url_to_check)
        
        # 2. Create a DataFrame for the model
        features_df = pd.DataFrame([url_features], columns=model_columns)
        
        # 3. Make a prediction
        prediction = model.predict(features_df)
        
        # 4. Format the response
        result = "phishing" if prediction[0] == 1 else "safe"
        
        # --- THIS IS THE NEW PART ---
        # Get the calculated Domain Age from our features dictionary
        domain_age = url_features.get('DomainAge', -1) # Default to -1 if not found

        # 5. Send the result AND the domain_age back to the extension
        return jsonify({
            "result": result,
            "url": url_to_check,
            "domain_age": domain_age # Add the age to the response
        })
        # ---------------------------

    except Exception as e:
        print(f"An error occurred during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500
    

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