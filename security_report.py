from datetime import datetime


def generate_report(history):

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    if history.empty:

        return f"""

AI THREAT DETECTION SYSTEM
AUTOMATIC SECURITY REPORT

Generated:
{current_time}

No security events have been recorded.

"""


    total = len(history)


    critical = int(
        (history["severity"] == "Critical")
        .sum()
    )


    high = int(
        (history["severity"] == "High")
        .sum()
    )


    medium = int(
        (history["severity"] == "Medium")
        .sum()
    )


    low = int(
        (history["severity"] == "Low")
        .sum()
    )


    average_score = (
        history["threat_score"].mean()
    )


    most_common_threat = (
        history["threat_type"]
        .value_counts()
        .idxmax()
    )


    report = f"""

=======================================================
          AI THREAT DETECTION SYSTEM
             SECURITY REPORT
=======================================================

Generated:
{current_time}


---------------- SECURITY SUMMARY ----------------

Total Events:
{total}

Critical Threats:
{critical}

High Threats:
{high}

Medium Threats:
{medium}

Low Threats:
{low}

Average Threat Score:
{average_score:.2f}%


Most Common Threat:
{most_common_threat}


---------------- RECENT EVENTS ----------------

"""


    for _, row in history.tail(10).iloc[::-1].iterrows():

        report += f"""

Time:
{row['timestamp']}

Device:
{row['device_id']}

Threat:
{row['threat_type']}

Severity:
{row['severity']}

Threat Score:
{row['threat_score']}%

-----------------------------------------------
"""


    report += """

RECOMMENDATION

High and Critical events should be investigated first.

Review:

• Device identity
• Login activity
• Network behavior
• File access
• Security logs

This report was generated automatically by
the AI Threat Detection System.

NOTE:
This is an educational cybersecurity prototype.
It does not replace a production SIEM, IDS/IPS,
EDR or Security Operations Center.

"""


    return report