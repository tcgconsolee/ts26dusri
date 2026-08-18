from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def home():
    """Renders the main INCC Protocol dashboard."""
    return render_template("index.html")


@app.route("/announcements")
def announcements():
    """Renders the announcements section."""
    return render_template("announcements.html")


@app.route("/supplies")
def supplies():
    """Renders the supplies management section."""
    return render_template("supplies.html")

@app.route("/sanitisation")
def sanitisation():
    return render_template("sanitisation.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)