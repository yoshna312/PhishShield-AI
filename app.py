from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishShield AI</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #0b1120; color: #f1f5f9;
}
header {
    padding: 24px 8%; border-bottom: 1px solid #293750;
    color: #60a5fa; font-size: 24px; font-weight: bold;
}
main { max-width: 850px; margin: 55px auto; padding: 20px; }
.card {
    background: #151f33; border: 1px solid #293750;
    border-radius: 18px; padding: 30px;
}
.tag { color: #6ee7b7; font-size: 12px; letter-spacing: 1px; }
h1 { font-size: 34px; }
p { color: #bac7da; line-height: 1.6; }
label { display: block; margin: 25px 0 10px; }
input {
    width: 100%; padding: 15px; border-radius: 9px;
    border: 1px solid #40516c; background: #0b1120;
    color: white; font-size: 15px;
}
button {
    width: 100%; margin-top: 14px; padding: 15px;
    border: 0; border-radius: 9px; background: #2878e5;
    color: white; font-weight: bold; font-size: 16px;
    cursor: pointer;
}
button:hover { background: #1d65c4; }
.result {
    margin-top: 25px; padding: 20px; border-radius: 12px;
    background: #202e47; overflow-wrap: anywhere;
}
ul { color: #d5deeb; line-height: 1.9; }
footer { text-align: center; color: #8493aa; padding: 25px; }
.small { font-size: 12px; }
</style>
</head>
<body>
<header>🛡️ PhishShield AI</header>
<main>
<section class="card">
<div class="tag">CYBERSECURITY • URL ANALYSIS</div>
<h1>Stay one step ahead of scams.</h1>
<p>Check a URL for suspicious characteristics and understand
the warning signs before opening it.</p>

<form method="POST">
<label for="url">Enter a URL to analyze</label>
<input id="url" name="url" type="text"
placeholder="https://example.com" required
value="{{ submitted }}">
<button type="submit">Analyze Threat</button>
</form>

{% if result %}
<div class="result">
<h2>{{ result.category }}</h2>
<h3>Risk score: {{ result.score }}/100</h3>
<p>{{ result.summary }}</p>
<strong>Indicators found</strong>
<ul>
{% for reason in result.reasons %}
<li>{{ reason }}</li>
{% endfor %}
</ul>
<p class="small">This is a heuristic assessment, not a guarantee
that a URL is safe or malicious.</p>
</div>
{% endif %}
</section>
</main>
<footer>PhishShield AI | Cybersecurity Minor Project</footer>
</body>
</html>
"""


def analyze_url(raw_url):
    value = raw_url.strip()
    reasons = []
    score = 0

    if not value:
        return None

    # Parse the URL without visiting the website.
    candidate = value if "://" in value else "https://" + value
    parsed = urlparse(candidate)
    host = parsed.hostname

    if not host or " " in value:
        return {
            "score": 0,
            "category": "Invalid URL",
            "summary": "Please enter a valid URL or domain name.",
            "reasons": ["The input could not be parsed as a URL."]
        }

    if parsed.scheme.lower() not in ("http", "https"):
        return {
            "score": 0,
            "category": "Unsupported URL",
            "summary": "Only HTTP and HTTPS URLs can be analyzed.",
            "reasons": ["Use a URL beginning with http:// or https://."]
        }

    if len(value) > 100:
        score += 10
        reasons.append("The URL is unusually long.")

    if "@" in parsed.netloc:
        score += 25
        reasons.append("The URL contains @ in its authority section.")

    if parsed.scheme.lower() == "http":
        score += 10
        reasons.append("The URL uses HTTP rather than HTTPS.")

    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("The hostname is an IP address instead of a domain.")
    except ValueError:
        pass

    if host.count(".") >= 4:
        score += 15
        reasons.append("The hostname contains many subdomain levels.")

    if "-" in host:
        score += 5
        reasons.append("The hostname contains a hyphen.")

    suspicious_words = (
        "login", "verify", "password", "update",
        "secure", "account", "bank", "wallet"
    )
    found_words = [word for word in suspicious_words
                   if word in (host + parsed.path).lower()]

    if found_words:
        score += min(20, len(found_words) * 10)
        reasons.append(
            "Contains potentially sensitive terms: "
            + ", ".join(found_words)
        )

    score = min(score, 100)

    if score >= 50:
        category = "High Risk Indicators"
        summary = "Several warning signs were detected. Avoid opening it until verified."
    elif score >= 25:
        category = "Medium Risk Indicators"
        summary = "Some warning signs were detected. Verify the domain independently."
    else:
        category = "Low Risk Indicators"
        summary = "Few of the implemented warning signs were detected. This does not prove the URL is safe."

    if not reasons:
        reasons.append("No warning signs covered by the current rules were detected.")

    return {
        "score": score,
        "category": category,
        "summary": summary,
        "reasons": reasons
    }


@app.route("/", methods=["GET", "POST"])
def home():
    submitted = ""
    result = None

    if request.method == "POST":
        submitted = request.form.get("url", "")[:2048]
        result = analyze_url(submitted)

    return render_template_string(
        HTML, submitted=submitted, result=result
    )


if __name__ == "__main__":
    app.run(debug=True)