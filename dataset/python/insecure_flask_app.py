from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)
api_key = "demo-api-key-do-not-use"


@app.route("/lookup")
def lookup_user():
    username = request.args.get("user", "")
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT id, email FROM users WHERE name = '{username}'")
    return {"rows": cursor.fetchall()}


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    completed = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": completed.stdout}


if __name__ == "__main__":
    app.run(debug=True)

