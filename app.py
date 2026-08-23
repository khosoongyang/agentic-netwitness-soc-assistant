"""Local launcher for the canonical Aegis Flask application."""

from backend.app import create_app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
