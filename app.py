import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime

from threat_model import (
    predict_threat,
    severity_from_score,
    get_recommendation
)

from security_report import generate_report

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI Threat Detection System",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# FILE PATHS
# --------------------------------------------------

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

HISTORY_FILE = DATA_DIR / "threat_history.csv"
DEVICES_FILE = DATA_DIR / "known_devices.json"


# --------------------------------------------------
# CREATE FILES IF NOT EXISTS
# --------------------------------------------------

if not HISTORY_FILE.exists():

    pd.DataFrame(columns=[
        "timestamp",
        "device_id",
        "unknown_device",
        "failed_logins",
        "requests_per_minute",
        "data_transfer_mb",
        "file_access_count",
        "suspicious_file_access",
        "threat_score",
        "severity",
        "threat_type"
    ]).to_csv(HISTORY_FILE, index=False)


if not DEVICES_FILE.exists():

    DEVICES_FILE.write_text(
        json.dumps({
            "DEV-001": "Laptop",
            "DEV-002": "Office-PC",
            "DEV-003": "Mobile"
        }, indent=2)
    )


# --------------------------------------------------
# LOAD DEVICES
# --------------------------------------------------

def load_known_devices():

    try:
        return json.loads(
            DEVICES_FILE.read_text()
        )

    except Exception:
        return {}


# --------------------------------------------------
# SAVE THREAT EVENT
# --------------------------------------------------

def save_event(event):

    history = pd.read_csv(HISTORY_FILE)

    new_event = pd.DataFrame([event])

    history = pd.concat(
        [history, new_event],
        ignore_index=True
    )

    history.to_csv(
        HISTORY_FILE,
        index=False
    )


# --------------------------------------------------
# AUTOMATIC ALERT
# --------------------------------------------------

def automatic_alert(severity, threat_type, score):

    if severity == "Critical":

        st.error(
            f"🚨 CRITICAL ALERT\n\n"
            f"{threat_type}\n\n"
            f"Threat Score: {score:.1f}%"
        )

    elif severity == "High":

        st.error(
            f"🚨 HIGH THREAT DETECTED\n\n"
            f"{threat_type}\n\n"
            f"Threat Score: {score:.1f}%"
        )

    elif severity == "Medium":

        st.warning(
            f"⚠️ MEDIUM THREAT\n\n"
            f"{threat_type}\n\n"
            f"Threat Score: {score:.1f}%"
        )

    else:

        st.info(
            f"🔔 Low-risk activity\n\n"
            f"Threat Score: {score:.1f}%"
        )


# --------------------------------------------------
# MAIN TITLE
# --------------------------------------------------

st.title("🛡️ AI-Powered Threat Detection System")

st.caption(
    "AI-based security monitoring and threat analysis dashboard"
)


known_devices = load_known_devices()


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:

    st.header("⚙️ System Settings")

    device_id = st.text_input(
        "Device ID",
        "DEV-001"
    )

    auto_alert = st.checkbox(
        "🔔 Automatic Alerts",
        True
    )

    st.divider()

    st.subheader("🤖 Gemini AI")

    gemini_key = st.text_input(
        "Gemini API Key (Optional)",
        type="password"
    )

    st.info(
        "Gemini is optional. "
        "The threat detection system works without it."
    )


# --------------------------------------------------
# TABS
# --------------------------------------------------

tabs = st.tabs([
    "📊 Dashboard",
    "🔍 Threat Scanner",
    "📈 Threat History",
    "📶 Devices",
    "📝 Security Report"
])


# ==================================================
# DASHBOARD
# ==================================================

with tabs[0]:

    st.header("📊 Security Dashboard")

    history = pd.read_csv(
        HISTORY_FILE
    )

    if len(history) > 0:

        total_events = len(history)

        threats = int(
            history["severity"]
            .isin(["High", "Critical"])
            .sum()
        )

        critical = int(
            (history["severity"] == "Critical")
            .sum()
        )

        average_score = history[
            "threat_score"
        ].mean()

    else:

        total_events = 0
        threats = 0
        critical = 0
        average_score = 0


    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        total_events
    )

    col2.metric(
        "High/Critical Threats",
        threats
    )

    col3.metric(
        "Critical Threats",
        critical
    )

    col4.metric(
        "Average Threat Score",
        f"{average_score:.1f}%"
    )


    st.divider()

    if len(history) > 0:

        st.subheader(
            "Latest Security Events"
        )

        st.dataframe(
            history.tail(10)
            .iloc[::-1],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No security events yet. "
            "Go to Threat Scanner and run an analysis."
        )


# ==================================================
# THREAT SCANNER
# ==================================================

with tabs[1]:

    st.header("🔍 Real-Time Threat Scanner")

    col1, col2 = st.columns(2)


    # ----------------------------------------------
    # DEVICE + LOGIN
    # ----------------------------------------------

    with col1:

        st.subheader(
            "📶 Device & Authentication"
        )

        device_known = st.checkbox(
            "Device is known",
            value=device_id in known_devices
        )

        failed_logins = st.number_input(
            "🔐 Failed Login Attempts",
            min_value=0,
            max_value=100,
            value=0
        )

        file_access_count = st.number_input(
            "📁 File Accesses in 5 Minutes",
            min_value=0,
            max_value=500,
            value=5
        )


    # ----------------------------------------------
    # NETWORK + FILES
    # ----------------------------------------------

    with col2:

        st.subheader(
            "🌐 Network & Files"
        )

        requests_per_minute = st.number_input(
            "🌐 Requests Per Minute",
            min_value=0,
            max_value=5000,
            value=20
        )

        data_transfer_mb = st.number_input(
            "📡 Data Transfer (MB)",
            min_value=0.0,
            max_value=100000.0,
            value=10.0
        )

        suspicious_file_access = st.checkbox(
            "📁 Suspicious / Protected File Access"
        )


    st.divider()


    # ----------------------------------------------
    # ANALYZE BUTTON
    # ----------------------------------------------

    if st.button(
        "🧠 ANALYZE ACTIVITY",
        type="primary",
        use_container_width=True
    ):

        unknown_device = not device_known


        # AI prediction
        result = predict_threat(

            unknown_device=unknown_device,

            failed_logins=failed_logins,

            requests_per_minute=requests_per_minute,

            data_transfer_mb=data_transfer_mb,

            file_access_count=file_access_count,

            suspicious_file_access=suspicious_file_access
        )


        score = result["threat_score"]

        severity = severity_from_score(
            score
        )

        threat_type = result["threat_type"]

        recommendation = get_recommendation(
            threat_type,
            severity
        )


        # Event data
        event = {

            "timestamp":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "device_id":
                device_id,

            "unknown_device":
                unknown_device,

            "failed_logins":
                failed_logins,

            "requests_per_minute":
                requests_per_minute,

            "data_transfer_mb":
                data_transfer_mb,

            "file_access_count":
                file_access_count,

            "suspicious_file_access":
                suspicious_file_access,

            "threat_score":
                round(score, 2),

            "severity":
                severity,

            "threat_type":
                threat_type
        }


        save_event(event)


        st.session_state[
            "last_result"
        ] = {

            **event,

            "recommendation":
                recommendation,

            "reasons":
                result["reasons"]
        }


        st.success(
            "✅ Threat analysis completed."
        )


    # ----------------------------------------------
    # DISPLAY RESULT
    # ----------------------------------------------

    if "last_result" in st.session_state:

        result = st.session_state[
            "last_result"
        ]


        st.divider()

        st.subheader(
            "🚨 Threat Detection Result"
        )


        col1, col2, col3 = st.columns(3)


        prediction = (
            "🚨 THREAT"
            if result["threat_score"] >= 50
            else "✅ NORMAL"
        )


        col1.metric(
            "🧠 Prediction",
            prediction
        )

        col2.metric(
            "📊 Threat Score",
            f'{result["threat_score"]:.1f}%'
        )

        col3.metric(
            "🚨 Severity",
            result["severity"]
        )


        st.write(
            f"**Detected Threat:** "
            f"{result['threat_type']}"
        )


        st.write(
            f"**Recommendation:** "
            f"{result['recommendation']}"
        )


        if result["reasons"]:

            st.write(
                "**Detected Indicators:**"
            )

            for reason in result["reasons"]:

                st.write(
                    f"• {reason}"
                )


        # Automatic alert

        if auto_alert:

            automatic_alert(
                result["severity"],
                result["threat_type"],
                result["threat_score"]
            )


        # ------------------------------------------
        # GEMINI
        # ------------------------------------------

        st.subheader(
            "🤖 AI Security Explanation"
        )


        if gemini_key:

            try:

                from gemini_explainer import (
                    explain_with_gemini
                )

                with st.spinner(
                    "Gemini is analyzing the event..."
                ):

                    explanation = (
                        explain_with_gemini(
                            result,
                            gemini_key
                        )
                    )

                st.write(
                    explanation
                )

            except Exception as error:

                st.warning(
                    f"Gemini unavailable: {error}"
                )

        else:

            st.info(
                "Add a Gemini API key in the sidebar "
                "to generate a detailed AI explanation."
            )

            st.write(
                f"The system detected "
                f"**{result['threat_type']}** "
                f"with a threat probability of "
                f"**{result['threat_score']:.1f}%**."
            )


# ==================================================
# THREAT HISTORY
# ==================================================

with tabs[2]:

    st.header(
        "📈 Threat History"
    )

    history = pd.read_csv(
        HISTORY_FILE
    )


    if len(history) > 0:

        history["timestamp"] = pd.to_datetime(
            history["timestamp"]
        )


        st.subheader(
            "Threat Score Over Time"
        )

        chart_data = history.set_index(
            "timestamp"
        )["threat_score"]


        st.line_chart(
            chart_data
        )


        st.subheader(
            "Threat Severity Distribution"
        )


        severity_counts = (
            history["severity"]
            .value_counts()
        )


        st.bar_chart(
            severity_counts
        )


        st.subheader(
            "Complete Threat History"
        )


        st.dataframe(
            history.iloc[::-1],
            use_container_width=True,
            hide_index=True
        )


    else:

        st.info(
            "No threat history available."
        )


# ==================================================
# KNOWN DEVICES
# ==================================================

with tabs[3]:

    st.header(
        "📶 Device Management"
    )


    st.write(
        "Trusted devices currently registered:"
    )


    for device, name in known_devices.items():

        st.write(
            f"• **{device}** — {name}"
        )


    st.divider()


    st.subheader(
        "➕ Add Trusted Device"
    )


    new_device_id = st.text_input(
        "Device ID",
        key="new_device"
    )

    new_device_name = st.text_input(
        "Device Name",
        key="new_device_name"
    )


    if st.button(
        "Add Device"
    ):

        if new_device_id and new_device_name:

            known_devices[
                new_device_id
            ] = new_device_name


            DEVICES_FILE.write_text(
                json.dumps(
                    known_devices,
                    indent=2
                )
            )


            st.success(
                "Device added successfully."
            )

        else:

            st.warning(
                "Please enter both fields."
            )


# ==================================================
# SECURITY REPORT
# ==================================================

with tabs[4]:

    st.header(
        "📝 Automatic Security Report"
    )


    history = pd.read_csv(
        HISTORY_FILE
    )


    if st.button(
        "📄 Generate Security Report"
    ):

        report = generate_report(
            history
        )


        st.text_area(
            "Report Preview",
            report,
            height=500
        )


        st.download_button(
            "⬇️ Download Security Report",
            report,
            file_name="security_report.txt",
            mime="text/plain"
        )

    else:

        st.info(
            "Click Generate Security Report "
            "to create an automatic report."
        )