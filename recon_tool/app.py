from flask import Flask, render_template, request, redirect, send_file
import subprocess
import os
import time

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        selected_modules = request.form.getlist('modules')

        flags = []
        for module in selected_modules:
            flags.append(f"--{module}")

        # Run the recon script
        output_file = f"reports/{domain}_report.html"
        command = ["python3.12", "intermediate_recon.py", domain] + flags + ["--output", "json"]
        subprocess.run(command)

        time.sleep(2)

        if os.path.exists(output_file):
            return redirect(f"/report/{domain}")
        else:
            return "Error: Report not found"

    return render_template("form.html")

@app.route("/report/<domain>")
def view_report(domain):
    path = f"reports/{domain}_report.html"
    if os.path.exists(path):
        return send_file(path)
    else:
        return "Report not found."

if __name__ == "__main__":
    print("[*] Starting Flask Recon UI at http://0.0.0.0:5000/")
    app.run(debug=True, host="0.0.0.0")
