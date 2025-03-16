import os
import requests
import hashlib
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# ========== CẤU HÌNH API KEYS ==========
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VIRUSTOTAL_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
MALWAREBAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"
IPQUALITYSCORE_API_KEY = "n4IFLrRkwD0tPTlJiiZGJC2lZtms8mIR"

# ========== HÀM HỖ TRỢ ==========
def get_url_id(url: str) -> str:
    """Tính SHA256 của URL để làm ID cho VirusTotal."""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

# --- Phân tích IP ---
def get_ipqualityscore_ip(ip: str) -> dict:
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip}"
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.json()
    else:
        return {"error": f"HTTP {resp.status_code}"}

def get_vt_ip(ip: str) -> str:
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            # Dùng trường "reputation" làm Community Score (mẫu báo cáo: 0)
            reputation = data.get("reputation", 0)
            return f"Community Score: {reputation}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

def get_abuseipdb(ip: str) -> str:
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return f"Confidence Score: {score}%"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

# --- Phân tích URL ---
def get_vt_url(url: str) -> str:
    try:
        url_id = get_url_id(url)
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # Ví dụ mẫu: Community Score: 13/94 (malicious/undetected)
            malicious = data.get("malicious", 0)
            undetected = data.get("undetected", 0)
            return f"Community Score: {malicious}/{undetected}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

def get_ipqs_url(url: str) -> str:
    try:
        qs_url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_API_KEY}/{url}"
        resp = requests.get(qs_url)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success", False):
                fraud_score = data.get("fraud_score", "N/A")
                return f"Fraud Score: {fraud_score}"
            else:
                return f"Error: {data.get('message', 'Unknown error')}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

# --- Phân tích Domain ---
def get_vt_domain(domain: str) -> str:
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            return f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

# --- Phân tích Hash ---
def get_vt_hash(file_hash: str) -> str:
    try:
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            return f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

def get_mb_hash(file_hash: str) -> str:
    try:
        mb_url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": file_hash}
        headers = {"API-KEY": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY != "YOUR_MALWAREBAZAAR_API_KEY" else {}
        resp = requests.post(mb_url, data=data, headers=headers)
        if resp.status_code == 200:
            mb_data = resp.json()
            if mb_data.get("query_status") == "ok":
                return "Hash found in MalwareBazaar"
            else:
                return "Hash not found in MalwareBazaar"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"

# ========== TELEGRAM HANDLERS ==========
async def analyze_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập IP, ví dụ: /analyze_ip 45.26.143.221")
        return
    ip = context.args[0]
    ipqs_info = get_ipqualityscore_ip(ip)
    if "error" not in ipqs_info:
        isp = ipqs_info.get("isp", "N/A")
        domain = ipqs_info.get("domain", "N/A")
        hostname = ipqs_info.get("hostname", [])
        country = ipqs_info.get("country_name", "N/A")
        conn_type = ipqs_info.get("connection_type", "N/A")
        proxy = ipqs_info.get("proxy", False)
        vpn = ipqs_info.get("vpn", False)
        tor = ipqs_info.get("tor", False)
        org = ipqs_info.get("organization", "N/A")
        fraud_score = ipqs_info.get("fraud_score", "N/A")
        details = (
            f"ISP: {isp}\n"
            f"Domain: {domain}\n"
            f"Hostname: {hostname}\n"
            f"Country Name: {country}\n"
            f"Type: {conn_type}\n"
            f"Proxy: {proxy} | VPN: {vpn} | Tor: {tor} | Org: {org}\n"
        )
    else:
        details = f"IPQualityScore Error: {ipqs_info.get('error')}\n"
        fraud_score = "N/A"
    vt_result = get_vt_ip(ip)
    abuse_result = get_abuseipdb(ip)
    report = (
        f"**Báo Cáo Phân Tích IP**\n"
        f"IP: {ip}\n"
        f"{details}"
        f"- VirusTotal: {vt_result} 🟢 - [View Detail](https://www.virustotal.com/gui/ip-address/{ip})\n"
        f"- AbuseIPDB: {abuse_result} 🟢 - [View Detail](https://www.abuseipdb.com/check/{ip})\n"
        f"- IPQualityScore: Fraud Score: {fraud_score}% 🟢 - [View Detail](https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip})"
    )
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL, ví dụ: /analyze_url br-icloud.com.br")
        return
    url = context.args[0]
    vt_result = get_vt_url(url)
    # IBM X-Force free version không hỗ trợ, hiển thị "Hết free"
    xforce_result = "Hết free"
    ipqs_result = get_ipqs_url(url)
    url_id = get_url_id(url)
    report = (
        f"**Báo Cáo Phân Tích URL**\n"
        f"URL: {url}\n"
        f"- VirusTotal: {vt_result} 🔴 - [View Detail](https://www.virustotal.com/gui/url/{url_id})\n"
        f"- IBM X-Force Exchange: {xforce_result} - [View Detail](https://exchange.xforce.ibmcloud.com/ip/{url})\n"
        f"- IPQualityScore: {ipqs_result} 🔴 - [View Detail](https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner/{url})"
    )
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập domain, ví dụ: /analyze_domain example.com")
        return
    domain = context.args[0]
    vt_result = get_vt_domain(domain)
    report = (
        f"**Báo Cáo Phân Tích Domain**\n"
        f"Domain: {domain}\n"
        f"- VirusTotal: {vt_result} 🔴 - [View Detail](https://www.virustotal.com/gui/domain/{domain})"
    )
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash, ví dụ: /analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31")
        return
    file_hash = context.args[0]
    vt_result = get_vt_hash(file_hash)
    mb_result = get_mb_hash(file_hash)
    report = (
        f"**Báo Cáo Phân Tích Hash**\n"
        f"Hash: {file_hash}\n"
        f"- VirusTotal: {vt_result} 🔴 - [View Detail](https://www.virustotal.com/gui/file/{file_hash})\n"
        f"- MalwareBazaar: {mb_result}"
    )
    await update.message.reply_text(report, parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "💡 **Danh sách lệnh:**\n"
        "/analyze_ip <IP> - Phân tích thông tin IP\n"
        "/analyze_url <URL> - Phân tích thông tin URL\n"
        "/analyze_domain <domain> - Phân tích domain\n"
        "/analyze_hash <hash> - Phân tích hash file\n"
        "\nVí dụ:\n"
        "`/analyze_ip 45.26.143.221`\n"
        "`/analyze_url br-icloud.com.br`\n"
        "`/analyze_domain example.com`\n"
        "`/analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31`"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Xin chào! Gõ /help để xem hướng dẫn sử dụng.")


def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("analyze_ip", analyze_ip))
    app.add_handler(CommandHandler("analyze_url", analyze_url))
    app.add_handler(CommandHandler("analyze_domain", analyze_domain))
    app.add_handler(CommandHandler("analyze_hash", analyze_hash))
    print("🤖 Bot đang chạy...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
