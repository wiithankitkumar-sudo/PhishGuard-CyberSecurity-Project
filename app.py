from flask import Flask, render_template, request
from detector import analyze_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    entered_url = ""

    if request.method == "POST":
        entered_url = request.form.get("url", "").strip()
        result = analyze_url(entered_url)

    return render_template(
        "index.html",
        result=result,
        entered_url=entered_url
    )


if __name__ == "__main__":
    app.run(debug=True)