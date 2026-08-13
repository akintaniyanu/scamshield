from flask import Flask, render_template, request

from flask_talisman import Talisman

from database import (
    init_database,
    save_scan,
    get_scans
)


app = Flask(__name__)

Talisman(app, force_https=False)

MAX_INPUT_LENGTH = 5000

init_database()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    input_type = request.form.get("input_type")

    input_value = request.form.get(
        "input_value",
        ""
    ).strip()

    # Check for empty input
    if not input_value:

        return render_template(
            "result.html",
            error="Please enter something to analyze."
        )

    # Check input length
    if len(input_value) > MAX_INPUT_LENGTH:

        return render_template(
            "result.html",
            error="Input is too long. Maximum length is 5000 characters."
        )

    # Analyze the input
    if input_type == "url":

        result = analyze_url(input_value)

    elif input_type == "message":

        result = analyze_message(input_value)

    elif input_type == "email":

        result = analyze_email(input_value)

    elif input_type == "phone":

        result = analyze_phone(input_value)

    else:

        return render_template(
            "result.html",
            error="Invalid input type."
        )

    # Save scan to database
    save_scan(
        input_type,
        input_value,
        result["risk_level"],
        result["score"],
        "\n".join(result["reasons"])
    )

    return render_template(
        "result.html",
        result=result,
        input_type=input_type,
        input_value=input_value
    )


@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

@app.route("/dashboard")
def dashboard():

    statistics = get_statistics()

    return render_template(
        "dashboard.html",
        statistics=statistics
    )

@app.route("/api/scan", methods=["POST"])
def api_scan():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "JSON body required"
        }), 400

    input_type = data.get("type")
    input_value = data.get("value", "").strip()

    if not input_type:
        return jsonify({
            "error": "Missing input type"
        }), 400

    if not input_value:
        return jsonify({
            "error": "Missing input value"
        }), 400

    if len(input_value) > 5000:
        return jsonify({
            "error": "Input is too long"
        }), 400

    if input_type == "url":

        result = analyze_url(input_value)

    elif input_type == "message":

        result = analyze_message(input_value)

    elif input_type == "email":

        result = analyze_email(input_value)

    elif input_type == "phone":

        result = analyze_phone(input_value)

    else:

        return jsonify({
            "error": "Unsupported input type"
        }), 400

    save_scan(
        input_type,
        input_value,
        result["risk_level"],
        result["score"],
        "\n".join(result["reasons"])
    )

    return jsonify({
        "type": input_type,
        "risk": result["risk_level"],
        "score": result["score"],
        "reasons": result["reasons"]
    })
