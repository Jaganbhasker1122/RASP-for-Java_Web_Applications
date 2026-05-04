from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import re
import urllib.parse

app = Flask(__name__)
CORS(app)

# Load the model
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("Model loaded successfully.")
except FileNotFoundError:
    print("WARNING: model.pkl not found. Please run train.py first.")
    model = None

def extract_features(payload):
    # Decode URL encoding to check for raw encoding flags
    try:
        decoded = urllib.parse.unquote(payload)
        encoding_flag = 1 if payload != decoded else 0
    except Exception:
        decoded = payload
        encoding_flag = 0

    decoded_lower = decoded.lower()

    # Features
    length = len(payload)
    
    # Count special chars
    special_chars = re.sub(r'[a-zA-Z0-9\s]', '', payload)
    special_char_count = len(special_chars)
    
    # Check SQL Keywords
    sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'where', 'or', 'and', 'from']
    has_sql_keywords = 1 if any(word in decoded_lower for word in sql_keywords) else 0
    
    # Check Script Tags
    script_keywords = ['<script>', 'javascript:', 'onload=', 'onerror=', 'eval(', 'alert(']
    has_script_tags = 1 if any(word in decoded_lower for word in script_keywords) else 0

    return {
        'length': length,
        'special_char_count': special_char_count,
        'has_sql_keywords': has_sql_keywords,
        'has_script_tags': has_script_tags,
        'encoding_flag': encoding_flag
    }

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json()
    if not data or 'payload' not in data:
        return jsonify({"error": "Missing 'payload' in JSON body"}), 400

    payload = data['payload']
    
    # Extract features dynamically from payload
    features_dict = extract_features(payload)
    
    # Prepare DataFrame for model prediction
    features_df = pd.DataFrame([features_dict], columns=[
        'length', 'special_char_count', 'has_sql_keywords', 'has_script_tags', 'encoding_flag'
    ])
    
    # Get probability of class 1 (attack)
    probability = model.predict_proba(features_df)[0][1]
    prediction = int(probability >= 0.5)

    return jsonify({
        "probability": float(probability),
        "prediction": "attack" if prediction == 1 else "normal",
        "features": features_dict
    })

if __name__ == '__main__':
    # Use Waitress for production-ready local testing, or Flask default for rapid testing
    app.run(host='0.0.0.0', port=5000, debug=True)
