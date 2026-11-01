
from google import genai


def explain_with_gemini(result, api_key):

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity threat analysis assistant.

Analyze the following security event:

Threat Type: {result.get('threat_type', 'Unknown')}
Threat Score: {result.get('threat_score', 0)}%
Severity: {result.get('severity', 'Unknown')}
Device ID: {result.get('device_id', 'Unknown')}

Detected Indicators:
{result.get('reasons', [])}

Existing Recommendation:
{result.get('recommendation', 'No recommendation available')}

Provide your response using these headings:

1. Threat Explanation
2. Possible Security Risk
3. Recommended Actions
4. Prevention Measures

Use simple and clear English.
Give practical cybersecurity recommendations.
Do not claim that an attack is confirmed if the evidence is insufficient.
"""

        response = client.interactions.create(
            model="gemini-3.8-flash",
            input=prompt
        )

        return response.output_text

    except Exception as error:
        return f"Gemini AI Error: {error}"
    except Exception as error:
        error_message = str(error)

        if "503" in error_message or "UNAVAILABLE" in error_message:
            return (
                "Gemini AI is temporarily busy. "
                "Please try again after a few minutes.\n\n"
                "The rule-based threat detection result "
                "is still available."
            )

        return f"Gemini AI Error: {error_message}"