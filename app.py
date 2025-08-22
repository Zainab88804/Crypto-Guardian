from flask import Flask, render_template, request
import requests
import re

app = Flask(__name__)

ETHERSCAN_API_KEY = "7PX5MAUDRTZNH65JVYM2N9DBNS5I7FWZBQ"
VIRUSTOTAL_API_KEY = "ad35aec7ad71cf4b8ecb817b66b7dd50c0cfb1fd476404bf4f606541999f7c7c"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url_result = None
    wallet_result = None

    if request.method == "POST":
        if "token" in request.form:
            token_address = request.form["token"]
            result = check_token_scam(token_address)
        elif "phish_url" in request.form:
            url_to_check = request.form["phish_url"]
            url_result = check_phishing_url(url_to_check)
        elif "wallet_address" in request.form:
            wallet_address = request.form["wallet_address"]
            wallet_result = audit_wallet(wallet_address)

    return render_template("index.html", result=result, url_result=url_result, wallet_result=wallet_result)

def check_token_scam(token_address):
    code_url = "https://api.etherscan.io/api"
    code_params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": token_address,
        "apikey": ETHERSCAN_API_KEY
    }

    code_response = requests.get(code_url, params=code_params).json()
    code_result = code_response.get("result", "")

    if code_result == "0x":
        return {
            "message": "⚠️ No contract code found at this address. Not a valid token contract.",
            "info": None
        }

    source_url = "https://api.etherscan.io/api"
    source_params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": token_address,
        "apikey": ETHERSCAN_API_KEY
    }

    source_response = requests.get(source_url, params=source_params).json()

    if source_response.get("status") == "1" and source_response["result"]:
        source_info = source_response["result"][0]
        if source_info["ABI"] != "Contract source code not verified":
            return {
                "message": f"✅ Token is safe!<br><strong>Name:</strong> {source_info['ContractName']}<br><strong>Compiler:</strong> {source_info['CompilerVersion']}",
                "info": source_info
            }
        else:
            return {
                "message": "⚠️ Token contract exists, but source code is <strong>not verified</strong>. Might be suspicious.",
                "info": source_info
            }
    else:
        return {
            "message": "❌ Failed to fetch contract metadata from Etherscan.",
            "info": None
        }

def check_phishing_url(url):
    if url.strip().lower() == "http://test-malicious.example.com":
        return {"message": "⚠️ Unsafe (Test malicious URL)", "is_phish": True}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url_submission = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})

    if url_submission.status_code != 200:
        return {"message": "❌ Failed to submit URL to VirusTotal.", "is_phish": None}

    analysis_id = url_submission.json().get("data", {}).get("id")
    if not analysis_id:
        return {"message": "❌ No analysis ID returned from VirusTotal.", "is_phish": None}

    analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    if analysis_response.status_code != 200:
        return {"message": "❌ Failed to retrieve analysis report from VirusTotal.", "is_phish": None}

    stats = analysis_response.json().get("data", {}).get("attributes", {}).get("stats", {})
    if stats.get("malicious", 0) > 0:
        return {"message": "⚠️ VirusTotal flagged this URL as malicious!", "is_phish": True}
    else:
        return {"message": "✅ URL appears safe (VirusTotal).", "is_phish": False}

def audit_wallet(address):
    if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
        return {"message": "❌ Invalid wallet address format."}

    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url).json()

    if response.get("status") != "1":
        return {"message": "❌ Failed to fetch transaction history for this wallet."}

    transactions = response.get("result", [])
    contract_interactions = [tx for tx in transactions if tx.get("to") and tx["to"] != address and tx.get("input") != "0x"]

    if not contract_interactions:
        return {"message": "✅ No suspicious activity found in wallet."}

    if len(contract_interactions) > 10:
        return {"message": f"⚠️ Wallet interacted with {len(contract_interactions)} contracts. May require manual review."}

    return {"message": f"✅ Wallet shows {len(contract_interactions)} safe interactions. No major threats detected."}

if __name__ == "__main__":
    print("✅ Flask app is starting... Visit http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)


