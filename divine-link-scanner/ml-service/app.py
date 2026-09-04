from flask import Flask, request, jsonify
import math

app = Flask(__name__)


def calculate_risk(transaction):
    amount = float(transaction.get("amount", 0))
    transactions_today = int(transaction.get("transactions_today", 0))
    account_age_days = int(transaction.get("account_age_days", 0))
    is_new_device = bool(transaction.get("is_new_device", False))
    unusual_location = bool(transaction.get("unusual_location", False))

    score = 0
    reasons = []

    # Amount risk
    if amount >= 1000000:
        score += 35
        reasons.append("Very large transaction amount")
    elif amount >= 500000:
        score += 20
        reasons.append("Large transaction amount")
    elif amount >= 100000:
        score += 10
        reasons.append("Unusually high amount")

    # Transaction frequency
    if transactions_today >= 20:
        score += 25
        reasons.append("Unusually high transaction frequency")
    elif transactions_today >= 10:
        score += 15
        reasons.append("High transaction frequency")

    # Account age
    if account_age_days < 7:
        score += 20
        reasons.append("Very new account")
    elif account_age_days < 30:
        score += 10
        reasons.append("Recently created account")

    # Device
    if is_new_device:
        score += 10
        reasons.append("New or unrecognized device")

    # Location
    if unusual_location:
        score += 15
        reasons.append("Unusual transaction location")

    score = min(score, 100)

    if score >= 70:
        decision = "BLOCK"
        risk_level = "HIGH"
    elif score >= 40:
        decision = "REVIEW"
        risk_level = "MEDIUM"
    else:
        decision = "ALLOW"
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "decision": decision,
        "reasons": reasons
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "Fraud Detection ML Service"
    })


@app.route("/predict", methods=["POST"])
def predict():
    try:
        transaction = request.get_json()

        if not transaction:
            return jsonify({
                "error": "Transaction data is required"
            }), 400

        result = calculate_risk(transaction)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)