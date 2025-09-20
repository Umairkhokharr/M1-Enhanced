from flask import Flask, request, jsonify, render_template
import json
import time
import random
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)

# Enhanced merchant database with more realistic data
MERCHANT_DB = {
    "MCC_5411_12345": {
        "name": "Whole Foods Market",
        "category": "Grocery Store",
        "location": "123 Main St, New York, NY",
        "risk_level": "Low",
        "mcc_code": "5411",
        "business_age_months": 120,
        "chargeback_rate": 0.5,
        "avg_transaction": 85.50,
        "verification_status": "Verified"
    },
    "MCC_5812_67890": {
        "name": "McDonald's",
        "category": "Fast Food Restaurant", 
        "location": "456 Oak Ave, Los Angeles, CA",
        "risk_level": "Low",
        "mcc_code": "5812",
        "business_age_months": 240,
        "chargeback_rate": 1.2,
        "avg_transaction": 12.75,
        "verification_status": "Verified"
    },
    "MCC_5999_11111": {
        "name": "QuickCash Electronics",
        "category": "Electronics Store",
        "location": "999 Suspicious St, High Risk City, TX",
        "risk_level": "High",
        "mcc_code": "5999",
        "business_age_months": 2,
        "chargeback_rate": 8.5,
        "avg_transaction": 850.00,
        "verification_status": "Pending"
    },
    "MCC_4121_22222": {
        "name": "Uber Technologies",
        "category": "Transportation Service",
        "location": "San Francisco, CA",
        "risk_level": "Low",
        "mcc_code": "4121",
        "business_age_months": 180,
        "chargeback_rate": 0.8,
        "avg_transaction": 25.30,
        "verification_status": "Verified"
    },
    "MCC_7995_33333": {
        "name": "Lucky Winner Casino",
        "category": "Gambling",
        "location": "Las Vegas, NV",
        "risk_level": "High",
        "mcc_code": "7995",
        "business_age_months": 6,
        "chargeback_rate": 15.2,
        "avg_transaction": 500.00,
        "verification_status": "Under Review"
    },
    "MCC_5533_44444": {
        "name": "AutoParts Express",
        "category": "Automotive Parts",
        "location": "Detroit, MI",
        "risk_level": "Medium",
        "mcc_code": "5533",
        "business_age_months": 36,
        "chargeback_rate": 3.2,
        "avg_transaction": 150.75,
        "verification_status": "Verified"
    }
}

# Enhanced fraud detection with multiple categories
def detect_fraud(transaction_data, merchant_info):
    flags = []
    transaction_risk = 0
    merchant_risk = 0
    
    # === TRANSACTION-LEVEL FRAUD FLAGS ===
    
    # Velocity flags
    velocity = transaction_data.get('velocity', 0)
    if velocity > 15:
        flags.append("extreme_velocity")
        transaction_risk += 25
    elif velocity > 10:
        flags.append("high_velocity")
        transaction_risk += 15
    elif velocity > 5:
        flags.append("moderate_velocity")
        transaction_risk += 8
    
    # Amount flags
    amount = transaction_data.get('amount', 0)
    avg_merchant_amount = merchant_info.get('avg_transaction', 100)
    
    if amount > avg_merchant_amount * 10:
        flags.append("extreme_amount_anomaly")
        transaction_risk += 20
    elif amount > avg_merchant_amount * 5:
        flags.append("high_amount_anomaly")
        transaction_risk += 15
    elif amount > 2000:
        flags.append("high_value_transaction")
        transaction_risk += 10
    
    # Round number check
    if amount % 100 == 0 and amount >= 500:
        flags.append("round_number_amount")
        transaction_risk += 5
    
    # Geographic flags
    ip_location = transaction_data.get('ip_location', '')
    billing_location = transaction_data.get('billing_location', '')
    merchant_location = merchant_info.get('location', '')
    
    if ip_location != billing_location:
        flags.append("location_mismatch")
        transaction_risk += 20
    
    if "High Risk City" in ip_location:
        flags.append("high_risk_location")
        transaction_risk += 15
    
    # Check if transaction location is far from merchant
    if "NY" in merchant_location and "CA" in ip_location:
        flags.append("distant_transaction")
        transaction_risk += 10
    
    # Card flags
    card_number = transaction_data.get('card_number', '')
    if card_number in ['9999', '0000', '1111']:
        flags.append("suspicious_card_pattern")
        transaction_risk += 20
    
    if not transaction_data.get('card_valid', True):
        flags.append("invalid_card")
        transaction_risk += 30
    
    # Time-based flags
    hour = datetime.now().hour
    if hour < 6 or hour > 22:
        flags.append("unusual_timing")
        transaction_risk += 8
    
    # === MERCHANT-LEVEL FRAUD FLAGS ===
    
    # Business age flags
    business_age = merchant_info.get('business_age_months', 0)
    if business_age < 6:
        flags.append("new_merchant")
        merchant_risk += 20
    elif business_age < 12:
        flags.append("young_merchant")
        merchant_risk += 10
    
    # Chargeback rate flags
    chargeback_rate = merchant_info.get('chargeback_rate', 0)
    if chargeback_rate > 10:
        flags.append("extreme_chargeback_rate")
        merchant_risk += 25
    elif chargeback_rate > 5:
        flags.append("high_chargeback_rate")
        merchant_risk += 15
    elif chargeback_rate > 2:
        flags.append("elevated_chargeback_rate")
        merchant_risk += 8
    
    # Category risk flags
    high_risk_categories = ["Gambling", "Cryptocurrency", "Adult Entertainment", "Firearms"]
    medium_risk_categories = ["Electronics Store", "Jewelry", "Luxury Goods"]
    
    category = merchant_info.get('category', '')
    if category in high_risk_categories:
        flags.append("high_risk_category")
        merchant_risk += 20
    elif category in medium_risk_categories:
        flags.append("medium_risk_category")
        merchant_risk += 10
    
    # Verification status flags
    verification = merchant_info.get('verification_status', '')
    if verification == "Pending":
        flags.append("unverified_merchant")
        merchant_risk += 15
    elif verification == "Under Review":
        flags.append("merchant_under_review")
        merchant_risk += 20
    
    # === PATTERN-BASED FLAGS ===
    
    # Simulate ML-detected patterns
    if random.random() < 0.3:  # 30% chance for demo
        ml_patterns = ["unusual_spending_pattern", "device_anomaly", "behavioral_deviation"]
        detected_pattern = random.choice(ml_patterns)
        flags.append(f"ml_detected_{detected_pattern}")
        transaction_risk += random.randint(5, 15)
    
    # Network analysis flags
    if merchant_info.get('name') == "QuickCash Electronics":
        flags.append("connected_to_fraud_network")
        merchant_risk += 25
    
    return flags, min(transaction_risk, 100), min(merchant_risk, 100)

def get_decision(total_risk_score):
    if total_risk_score <= 25:
        return "APPROVE", "#28a745"  # Green
    elif total_risk_score <= 50:
        return "REVIEW", "#ffc107"   # Yellow
    elif total_risk_score <= 75:
        return "DECLINE", "#fd7e14"  # Orange
    else:
        return "BLOCK", "#dc3545"    # Red

def categorize_flags(flags):
    categories = {
        "Transaction Flags": [],
        "Merchant Flags": [],
        "Geographic Flags": [],
        "Timing Flags": [],
        "ML Detected": []
    }
    
    for flag in flags:
        if any(x in flag for x in ["velocity", "amount", "card", "round_number"]):
            categories["Transaction Flags"].append(flag)
        elif any(x in flag for x in ["merchant", "chargeback", "category", "verification"]):
            categories["Merchant Flags"].append(flag)
        elif any(x in flag for x in ["location", "distant", "high_risk_location"]):
            categories["Geographic Flags"].append(flag)
        elif any(x in flag for x in ["timing", "unusual_timing"]):
            categories["Timing Flags"].append(flag)
        elif "ml_detected" in flag:
            categories["ML Detected"].append(flag)
        else:
            categories["Transaction Flags"].append(flag)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze-transaction', methods=['POST'])
def analyze_transaction():
    try:
        data = request.json
        merchant_id = data.get('merchant_id', '')
        
        # Get merchant info
        merchant_info = MERCHANT_DB.get(merchant_id, {
            "name": "Unknown Merchant",
            "category": "Unknown Category", 
            "location": "Unknown Location",
            "risk_level": "Medium",
            "mcc_code": "0000",
            "business_age_months": 12,
            "chargeback_rate": 2.0,
            "avg_transaction": 100.00,
            "verification_status": "Pending"
        })
        
        # Detect fraud
        fraud_flags, transaction_risk, merchant_risk = detect_fraud(data, merchant_info)
        
        # Calculate combined risk score (weighted average)
        combined_risk_score = int((transaction_risk * 0.6) + (merchant_risk * 0.4))
        
        # Get decision
        decision, decision_color = get_decision(combined_risk_score)
        
        # Categorize flags
        categorized_flags = categorize_flags(fraud_flags)
        
        # Calculate processing time
        processing_time = random.randint(45, 95)  # 45-95ms
        
        # Generate transaction ID
        transaction_id = f"TXN_{str(uuid.uuid4())[:8].upper()}"
        
        result = {
            "transaction_id": transaction_id,
            "merchant_info": merchant_info,
            "fraud_analysis": {
                "all_flags": fraud_flags,
                "categorized_flags": categorized_flags,
                "transaction_risk_score": transaction_risk,
                "merchant_risk_score": merchant_risk,
                "combined_risk_score": combined_risk_score
            },
            "decision": decision,
            "decision_color": decision_color,
            "processing_time": f"{processing_time}ms",
            "timestamp": datetime.now().isoformat(),
            "recommendations": generate_recommendations(decision, fraud_flags, combined_risk_score)
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def generate_recommendations(decision, flags, risk_score):
    recommendations = []
    
    if decision == "APPROVE":
        recommendations.append("Transaction approved - continue processing")
        recommendations.append("Monitor for post-transaction anomalies")
    elif decision == "REVIEW":
        recommendations.append("Manual review recommended")
        recommendations.append("Verify customer identity before processing")
        if "location_mismatch" in flags:
            recommendations.append("Confirm transaction location with customer")
    elif decision == "DECLINE":
        recommendations.append("High fraud risk - decline transaction")
        recommendations.append("Send fraud alert to customer")
        if "high_chargeback_rate" in flags:
            recommendations.append("Consider blacklisting merchant")
    else:  # BLOCK
        recommendations.append("Immediate block - suspected fraud")
        recommendations.append("Investigate merchant and customer")
        recommendations.append("Report to fraud database")
    
    return recommendations

@app.route('/merchants')
def get_merchants():
    return jsonify(list(MERCHANT_DB.keys()))

@app.route('/merchant-stats')
def get_merchant_stats():
    stats = {}
    for merchant_id, info in MERCHANT_DB.items():
        stats[merchant_id] = {
            "name": info["name"],
            "risk_level": info["risk_level"],
            "chargeback_rate": info["chargeback_rate"],
            "business_age_months": info["business_age_months"]
        }
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True)
