import os
import pickle
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

from preprocessing.url_preprocessing import preprocess_url
from preprocessing.email_preprocessing import preprocess_email

# -------------------- APP CONFIG --------------------
app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- LOAD MODELS --------------------
URL_MODEL_PATH = os.path.join(BASE_DIR, "model", "url_model.h5")
EMAIL_MODEL_PATH = os.path.join(BASE_DIR, "model", "email_model.h5")

url_model = load_model(URL_MODEL_PATH)
email_model = load_model(EMAIL_MODEL_PATH)

# -------------------- LOAD TOKENIZERS --------------------
with open(os.path.join(BASE_DIR, "model", "tokenizer_url.pkl"), "rb") as f:
    tokenizer_url = pickle.load(f)

with open(os.path.join(BASE_DIR, "model", "tokenizer_email.pkl"), "rb") as f:
    tokenizer_email = pickle.load(f)

# -------------------- CONSTANTS --------------------
MAX_URL_LEN = 200
MAX_EMAIL_LEN = 300

URL_THRESHOLD = 0.4
EMAIL_THRESHOLD = 0.3   # 🔥 LOWER for social-engineering emails

# -------------------- TRUST LIST --------------------
TRUSTED_DOMAINS = {
    "google.com", "google.co.in",
    "amazon.com", "amazon.in",
    "flipkart.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "linkedin.com"
}

# -------------------- URL HEURISTICS --------------------
SUSPICIOUS_TLDS = {
    ".app", ".xyz", ".top", ".site", ".online",
    ".live", ".info", ".icu", ".store"
}

PHISHING_TOKENS = {
    "login", "secure", "verify", "account",
    "update", "confirm", "auth", "mirror",
    "bank", "wallet", "payment"
}

# -------------------- EMAIL HEURISTICS (UPDATED) --------------------
PHISHING_EMAIL_KEYWORDS = {
    "unusual activity",
    "new device",
    "verification required",
    "verify your account",
    "confirm your activity",
    "temporary restriction",
    "temporary restrictions",
    "service interruption",
    "pending review",
    "risk level",
    "action required",
    "24 hours",
    "security team",
    "account activity",
    "we detected",
    "automated message"
}

# -------------------- HEALTH CHECK --------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "Backend is running"})


# -------------------- URL PHISHING DETECTION --------------------
@app.route("/predict-url", methods=["POST"])
def predict_url():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    raw_url = data["url"].strip().lower()
    parsed = urlparse(raw_url)
    domain = parsed.netloc.replace("www.", "")

    # ---------- HARD RULE 1: Suspicious TLD ----------
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return jsonify({
            "prediction": "Phishing",
            "confidence": 0.92,
            "method": "heuristic",
            "reason": "Suspicious top-level domain"
        })

    # ---------- HARD RULE 2: Phishing Tokens ----------
    token_hits = sum(token in raw_url for token in PHISHING_TOKENS)
    if token_hits >= 1:
        return jsonify({
            "prediction": "Phishing",
            "confidence": 0.90,
            "method": "heuristic",
            "reason": "Phishing keyword patterns detected"
        })

    # ---------- ML MODEL ----------
    clean_url = preprocess_url(raw_url)
    sequence = tokenizer_url.texts_to_sequences([clean_url])
    padded = pad_sequences(sequence, maxlen=MAX_URL_LEN)

    probability = float(url_model.predict(padded)[0][0])
    prediction = "Phishing" if probability >= URL_THRESHOLD else "Legitimate"
    confidence = max(probability, 0.6)

    if domain in TRUSTED_DOMAINS and prediction == "Legitimate":
        confidence = max(confidence, 0.90)

    return jsonify({
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "method": "cnn+lstm"
    })


# -------------------- EMAIL PHISHING DETECTION --------------------
@app.route("/predict-email", methods=["POST"])
def predict_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Email text is required"}), 400

    raw_email = data["email"].lower()

    # ---------- HARD RULE: SOCIAL ENGINEERING ----------
    hits = sum(keyword in raw_email for keyword in PHISHING_EMAIL_KEYWORDS)

    if hits >= 2:
        confidence = min(0.85 + hits * 0.03, 0.98)
        return jsonify({
            "prediction": "Phishing",
            "confidence": round(confidence, 4),
            "method": "rule-based",
            "reason": "Social engineering language detected"
        })

    # ---------- ML MODEL ----------
    clean_email = preprocess_email(raw_email)
    sequence = tokenizer_email.texts_to_sequences([clean_email])
    padded = pad_sequences(sequence, maxlen=MAX_EMAIL_LEN)

    probability = float(email_model.predict(padded)[0][0])
    prediction = "Phishing" if probability >= EMAIL_THRESHOLD else "Legitimate"
    confidence = max(probability, 0.6)

    return jsonify({
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "method": "cnn+lstm"
    })


# -------------------- RUN SERVER --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)