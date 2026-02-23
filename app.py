from flask import Flask, render_template, request, redirect, session, jsonify
import re
import joblib
import numpy as np
from urllib.parse import urlparse

# =============================
# INIT APP
# =============================

app = Flask(__name__)
app.secret_key = "secret_key"


# =============================
# LOAD TRAINED MODEL
# =============================

data = joblib.load("model/phishing_model.pkl")

model = data["model"]
feature_columns = data["features"]

print("✅ Model loaded successfully")
print("✅ Total features:", len(feature_columns))


# =============================
# TEMP USER STORAGE
# =============================

users = {}


# =============================
# AUTH ROUTES
# =============================

@app.route("/")
def home():
    if "user" in session:
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username in users:
            return "User already exists"

        users[username] = password

        return redirect("/")

    return render_template("register.html")


@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    if username in users and users[username] == password:

        session["user"] = username
        return redirect("/dashboard")

    return "Invalid credentials"


@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/")


# =============================
# DASHBOARD ROUTES
# =============================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    return render_template("dashboard.html")


@app.route("/history")
def history():

    history_data = session.get("history", [])

    return render_template("history.html", history=history_data)


@app.route("/profile")
def profile():

    if "user" not in session:
        return redirect("/")

    return render_template("profile.html")


@app.route("/about")
def about():

    if "user" not in session:
        return redirect("/")

    return render_template("about.html")


@app.route("/contact")
def contact():

    if "user" not in session:
        return redirect("/")

    return render_template("contact.html")


@app.route("/guest")
def guest():

    session["user"] = "Guest"
    session["is_guest"] = True

    return redirect("/dashboard")


# =============================
# FEATURE EXTRACTION FUNCTION
# =============================

def extract_url_features(url):

    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}

    # URL basic features
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)
    features['IsDomainIP'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0

    # TLD
    features['TLD'] = 0
    features['TLDLength'] = len(domain.split('.')[-1]) if '.' in domain else 0

    # Similarity / probability features (not available → default 0)
    features['URLSimilarityIndex'] = 0
    features['CharContinuationRate'] = 0
    features['TLDLegitimateProb'] = 0
    features['URLCharProb'] = 0

    # Subdomains
    features['NoOfSubDomain'] = max(domain.count('.') - 1, 0)

    # Obfuscation
    features['HasObfuscation'] = 1 if '%' in url else 0
    features['NoOfObfuscatedChar'] = url.count('%')
    features['ObfuscationRatio'] = url.count('%') / len(url) if len(url) > 0 else 0

    # Letters and digits
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url) if len(url) > 0 else 0

    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url) if len(url) > 0 else 0

    # Special characters
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')

    special_chars = re.findall(r'[^\w]', url)

    features['NoOfOtherSpecialCharsInURL'] = len(special_chars)
    features['SpacialCharRatioInURL'] = len(special_chars) / len(url) if len(url) > 0 else 0

    # HTTPS
    features['IsHTTPS'] = 1 if parsed.scheme == "https" else 0

    # HTML / Page features (not available → default 0)
    features['LineOfCode'] = 0
    features['LargestLineLength'] = 0
    features['HasTitle'] = 0
    features['DomainTitleMatchScore'] = 0
    features['URLTitleMatchScore'] = 0
    features['HasFavicon'] = 0
    features['Robots'] = 0
    features['IsResponsive'] = 0
    features['NoOfURLRedirect'] = 0
    features['NoOfSelfRedirect'] = 0
    features['HasDescription'] = 0
    features['NoOfPopup'] = 0
    features['NoOfiFrame'] = 0
    features['HasExternalFormSubmit'] = 0
    features['HasSocialNet'] = 0
    features['HasSubmitButton'] = 0
    features['HasHiddenFields'] = 0
    features['HasPasswordField'] = 0

    # Keyword features
    features['Bank'] = 1 if "bank" in url.lower() else 0
    features['Pay'] = 1 if "pay" in url.lower() else 0
    features['Crypto'] = 1 if "crypto" in url.lower() else 0

    # Remaining features default 0
    features['HasCopyrightInfo'] = 0
    features['NoOfImage'] = 0
    features['NoOfCSS'] = 0
    features['NoOfJS'] = 0
    features['NoOfSelfRef'] = 0
    features['NoOfEmptyRef'] = 0
    features['NoOfExternalRef'] = 0

    # Ensure correct order
    feature_vector = [features[col] for col in feature_columns]

    return np.array(feature_vector).reshape(1, -1)


# =============================
# PREDICTION ROUTE
# =============================

@app.route("/predict", methods=["POST"])
def predict():

    data = request.json

    url = data.get("url")

    if not url:

        return jsonify({"error": "No URL provided"}), 400

    try:

        features = extract_url_features(url)

        prediction = model.predict(features)[0]

        probabilities = model.predict_proba(features)[0]

        phishing_probability = round(probabilities[1] * 100, 2)
        legitimate_probability = round(probabilities[0] * 100, 2)

        if prediction == 1:

            result = "🔴 Phishing"

        else:

            result = "🟢 Legitimate"

        # Save history
        if "history" not in session:

            session["history"] = []

        session["history"].append({

            "url": url,
            "result": result,
            "phishing": phishing_probability,
            "legitimate": legitimate_probability

        })

        session.modified = True

        return jsonify({

            "result": result,
            "phishing_probability": phishing_probability,
            "legitimate_probability": legitimate_probability

        })

    except Exception as e:

        return jsonify({

            "error": str(e)

        }), 500


# =============================
# RUN SERVER
# =============================

if __name__ == "__main__":

    app.run(debug=True)