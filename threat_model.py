def clamp(value, minimum=0, maximum=100):

    return max(
        minimum,
        min(maximum, value)
    )


def predict_threat(
    unknown_device,
    failed_logins,
    requests_per_minute,
    data_transfer_mb,
    file_access_count,
    suspicious_file_access
):

    score = 0

    reasons = []


    # ----------------------------------------------
    # UNKNOWN DEVICE
    # ----------------------------------------------

    if unknown_device:

        score += 22

        reasons.append(
            "Unknown device detected"
        )


    # ----------------------------------------------
    # BRUTE FORCE
    # ----------------------------------------------

    if failed_logins >= 5:

        score += min(
            35,
            failed_logins * 2.5
        )

        reasons.append(
            "Multiple failed login attempts"
        )


    # ----------------------------------------------
    # NETWORK TRAFFIC
    # ----------------------------------------------

    if requests_per_minute >= 100:

        score += min(
            25,
            10 +
            (requests_per_minute - 100) / 10
        )

        reasons.append(
            "Unusual network traffic"
        )


    # ----------------------------------------------
    # DATA TRANSFER
    # ----------------------------------------------

    if data_transfer_mb >= 500:

        score += min(
            20,
            data_transfer_mb / 100
        )

        reasons.append(
            "High data transfer"
        )


    # ----------------------------------------------
    # FILE ACCESS
    # ----------------------------------------------

    if file_access_count >= 50:

        score += min(
            20,
            file_access_count / 5
        )

        reasons.append(
            "Abnormal file access"
        )


    # ----------------------------------------------
    # SUSPICIOUS FILE
    # ----------------------------------------------

    if suspicious_file_access:

        score += 30

        reasons.append(
            "Protected or suspicious file accessed"
        )


    # ----------------------------------------------
    # MULTIPLE INDICATORS
    # ----------------------------------------------

    indicators = sum([
        bool(unknown_device),
        failed_logins >= 5,
        requests_per_minute >= 100,
        data_transfer_mb >= 500,
        file_access_count >= 50,
        suspicious_file_access
    ])


    if indicators >= 3:

        score += 15

        reasons.append(
            "Multiple suspicious indicators detected"
        )


    score = clamp(score)


    # ----------------------------------------------
    # THREAT TYPE
    # ----------------------------------------------

    if failed_logins >= 10:

        threat_type = (
            "Brute-force login attempt"
        )

    elif suspicious_file_access or file_access_count >= 50:

        threat_type = (
            "Abnormal file access"
        )

    elif (
        requests_per_minute >= 100
        or
        data_transfer_mb >= 500
    ):

        threat_type = (
            "Unusual network traffic"
        )

    elif unknown_device:

        threat_type = (
            "Unknown device"
        )

    else:

        threat_type = (
            "Normal activity"
        )


    return {

        "threat_score":
            round(score, 2),

        "threat_type":
            threat_type,

        "reasons":
            reasons
    }


# ==================================================
# SEVERITY
# ==================================================

def severity_from_score(score):

    if score >= 85:

        return "Critical"

    elif score >= 65:

        return "High"

    elif score >= 35:

        return "Medium"

    else:

        return "Low"


# ==================================================
# RECOMMENDATION
# ==================================================

def get_recommendation(
    threat_type,
    severity
):

    recommendations = {

        "Brute-force login attempt":
            "Review authentication logs, enable MFA, and temporarily lock the affected account if necessary.",

        "Abnormal file access":
            "Review accessed files and verify whether the user or device is authorized.",

        "Unusual network traffic":
            "Review network destinations, traffic volume, and the process generating the traffic.",

        "Unknown device":
            "Verify the device identity before allowing access to sensitive resources.",

        "Normal activity":
            "Continue normal security monitoring."
    }


    return recommendations.get(
        threat_type,
        "Continue investigation and monitoring."
    )

# ============================================
# AI-POWERED THREAT DETECTION SYSTEM
# Threat Detection Model
# ============================================


def predict_threat(
    unknown_device=False,
    failed_logins=0,
    requests_per_minute=0,
    data_transfer_mb=0,
    file_access_count=0,
    suspicious_file_access=False
):

    threat_score = 0
    reasons = []

    # 1. Unknown Device Detection
    if unknown_device:
        threat_score += 25
        reasons.append("Unknown or unregistered device detected")

    # 2. Brute Force Detection
    if failed_logins >= 10:
        threat_score += 30
        reasons.append("Possible brute-force login attack")

    elif failed_logins >= 5:
        threat_score += 20
        reasons.append("Multiple failed login attempts detected")

    elif failed_logins >= 3:
        threat_score += 10
        reasons.append("Repeated login failures detected")

    # 3. Unusual Network Traffic
    if requests_per_minute >= 1000:
        threat_score += 25
        reasons.append("Extremely high network request activity")

    elif requests_per_minute >= 500:
        threat_score += 15
        reasons.append("Unusual network request activity")

    # 4. Excessive Data Transfer
    if data_transfer_mb >= 1000:
        threat_score += 20
        reasons.append("Unusually large data transfer detected")

    elif data_transfer_mb >= 500:
        threat_score += 10
        reasons.append("High data transfer detected")

    # 5. Abnormal File Access
    if file_access_count >= 100:
        threat_score += 15
        reasons.append("Excessive file access activity detected")

    elif file_access_count >= 50:
        threat_score += 10
        reasons.append("Unusual file access frequency detected")

    # 6. Suspicious Protected File Access
    if suspicious_file_access:
        threat_score += 25
        reasons.append("Suspicious access to protected files detected")

    # Keep score within 0 to 100
    threat_score = min(threat_score, 100)

    # Identify threat type
    if not reasons:
        threat_type = "Normal Activity"

    elif len(reasons) > 1:
        threat_type = "Multiple Security Threats"

    else:
        threat_type = reasons[0]

    return {
        "threat_score": threat_score,
        "threat_type": threat_type,
        "reasons": reasons
    }


# ============================================
# SEVERITY CLASSIFICATION
# ============================================

def severity_from_score(score):

    if score >= 75:
        return "Critical"

    elif score >= 50:
        return "High"

    elif score >= 25:
        return "Medium"

    else:
        return "Low"


# ============================================
# SECURITY RECOMMENDATIONS
# ============================================

def get_recommendation(threat_type, severity):

    if severity == "Critical":
        return (
            "Immediately investigate the activity, "
            "verify the affected device, and take "
            "appropriate security measures."
        )

    elif severity == "High":
        return (
            "Investigate the suspicious activity, "
            "review login records, and check network traffic."
        )

    elif severity == "Medium":
        return (
            "Monitor the activity and verify whether "
            "the behavior is authorized."
        )

    else:
        return (
            "Activity appears to be low risk. "
            "Continue regular security monitoring."
        )
