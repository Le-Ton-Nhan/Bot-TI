import os
import requests
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

# ========== CONFIGURATION ==========
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VIRUSTOTAL_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"
MALWAREBAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"
IPQUALITYSCORE_API_KEY = "n4IFLrRkwD0tPTlJiiZGJC2lZtms8mIR"


# ========== API CALL FUNCTIONS ==========

def check_ip_virustotal(ip: str) -> str:
    """Call VirusTotal cho IP, trả về 'Community Score'."""
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            # Lấy trường 'reputation' – tương đương Community Score
            reputation = vt_json.get("data", {}).get("attributes", {}).get("reputation", "N/A")
            return f"Community Score: {reputation}"
        else:
            return f"Error {vt_resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


def check_ip_abuseipdb(ip: str) -> str:
    """Call AbuseIPDB cho IP."""
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        resp = requests.get(abuse_url, headers=headers, params=params)
        if resp.status_code == 200:
            abuse_json = resp.json()
            score = abuse_json.get("data", {}).get("abuseConfidenceScore", "N/A")
            return f"Confidence Score: {score}%"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


def check_ipqualityscore(ip: str) -> dict:
    """Call IPQualityScore API để lấy thông tin chi tiết về IP."""
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip}"
        resp = requests.get(url)
        if resp.status_code == 200:
            ipqs_json = resp.json()
            if ipqs_json.get("success", False):
                return ipqs_json
            else:
                return {"error": ipqs_json.get("message", "Unknown error")}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_domain_virustotal(domain: str) -> str:
    """Call VirusTotal cho phân tích domain."""
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            return f"Error {vt_resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


def check_hash_virustotal(file_hash: str) -> str:
    """Call VirusTotal cho phân tích hash file."""
    try:
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            return f"Error {vt_resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


def check_hash_malwarebazaar(file_hash: str) -> str:
    """Call MalwareBazaar cho phân tích hash file."""
    try:
        mb_url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": file_hash}
        headers = {"API-KEY": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY != "YOUR_MALWAREBAZAAR_API_KEY" else {}
        resp = requests.post(mb_url, data=data, headers=headers)
        if resp.status_code == 200:
            mb_json = resp.json()
            if mb_json.get("query_status") == "ok":
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
    # Lấy thông tin chi tiết từ IPQualityScore
    ipqs_result = check_ipqualityscore(ip)
    
    report = f"**Báo Cáo Phân Tích IP**\n"
    report += f"IP: {ip}\n"
    if "error" not in ipqs_result:
        isp = ipqs_result.get("isp", "N/A")
        domain = ipqs_result.get("domain", "N/A")
        hostname = ipqs_result.get("hostname", "N/A")
        country = ipqs_result.get("country_name", "N/A")
        connection_type = ipqs_result.get("connection_type", "N/A")
        proxy = ipqs_result.get("proxy", False)
        vpn = ipqs_result.get("vpn", False)
        tor = ipqs_result.get("tor", False)
        organization = ipqs_result.get("organization", "N/A")
        report += f"ISP: {isp}\n"
        report += f"Domain: {domain}\n"
        report += f"Hostname: {hostname}\n"
        report += f"Country Name: {country}\n"
        report += f"Type: {connection_type}\n"
        report += f"Proxy: {proxy} | VPN: {vpn} | Tor: {tor} | Org: {organization}\n"
    else:
        report += f"IPQualityScore: {ipqs_result.get('error')}\n"
    
    vt_result = check_ip_virustotal(ip)
    abuse_result = check_ip_abuseipdb(ip)
    fraud_score = ipqs_result.get("fraud_score", "N/A") if "error" not in ipqs_result else "N/A"
    
    report += f"- VirusTotal: {vt_result} 🟢 - [View Detail](https://www.virustotal.com/gui/ip-address/{ip})\n"
    report += f"- AbuseIPDB: {abuse_result} 🟢 - [View Detail](https://www.abuseipdb.com/check/{ip})\n"
    report += f"- IPQualityScore: Fraud Score: {fraud_score}% 🟢 - [View Detail](https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip})"
    
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL, ví dụ: /analyze_url https://br-icloud.com.br")
        return
    url = context.args[0]
    # Lấy kết quả từ VirusTotal và IBM X-Force cho URL
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_data = {"url": url}
        vt_resp = requests.post(vt_url, headers=vt_headers, data=vt_data)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            analysis_id = vt_json.get("data", {}).get("id", "N/A")
            vt_detail = f"Analysis ID: {analysis_id}"
        else:
            vt_detail = f"Error {vt_resp.status_code}"
    except Exception as e:
        vt_detail = f"Exception: {e}"
    
    # IBM X-Force cho URL (nếu có quyền truy cập)
    try:
        xforce_url = f"https://api.xforce.ibmcloud.com/url/{url}"
        auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
        xforce_resp = requests.get(xforce_url, auth=auth)
        if xforce_resp.status_code == 200:
            xforce_json = xforce_resp.json()
            score = xforce_json.get("score", "N/A")
            xforce_detail = f"Score: {score}"
        else:
            xforce_detail = f"Error {xforce_resp.status_code}"
    except Exception as e:
        xforce_detail = f"Exception: {e}"
    
    report = f"**Báo Cáo Phân Tích URL**\nURL: {url}\n"
    report += f"- VirusTotal: {vt_detail} 🟢 - [View Detail](https://www.virustotal.com/gui/url/{url})\n"
    report += f"- IBM X-Force: {xforce_detail} 🟢 - [View Detail](https://exchange.xforce.ibmcloud.com/url/{url})"
    
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập domain, ví dụ: /analyze_domain example.com")
        return
    domain = context.args[0]
    vt_detail = check_domain_virustotal(domain)
    report = f"**Báo Cáo Phân Tích Domain**\nDomain: {domain}\n"
    report += f"- VirusTotal: {vt_detail} 🟢 - [View Detail](https://www.virustotal.com/gui/domain/{domain})"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash, ví dụ: /analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31")
        return
    file_hash = context.args[0]
    vt_detail = check_hash_virustotal(file_hash)
    mb_detail = check_hash_malwarebazaar(file_hash)
    report = f"**Báo Cáo Phân Tích Hash**\nHash: {file_hash}\n"
    report += f"- VirusTotal: {vt_detail} 🟢 - [View Detail](https://www.virustotal.com/gui/file/{file_hash})\n"
    report += f"- MalwareBazaar: {mb_detail}"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Placeholder, không tích hợp HIBP
    if not context.args:
        await update.message.reply_text("Vui lòng nhập email, ví dụ: /analyze_email test@example.com")
        return
    email = context.args[0]
    report = f"**Báo Cáo Phân Tích Email**\nEmail: {email}\n"
    report += "- Kết quả: Chức năng kiểm tra email chưa được tích hợp."
    await update.message.reply_text(report, parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "💡 **Danh sách lệnh:**\n"
        "/analyze_ip <IP> - Phân tích thông tin IP\n"
        "/analyze_url <URL> - Kiểm tra thông tin URL\n"
        "/analyze_domain <domain> - Lấy thông tin domain\n"
        "/analyze_hash <hash> - Phân tích hash file\n"
        "/analyze_email <email> - Kiểm tra email (placeholder)\n"
        "\nVí dụ:\n"
        "`/analyze_ip 45.26.143.221`\n"
        "`/analyze_url https://br-icloud.com.br`\n"
        "`/analyze_domain example.com`\n"
        "`/analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31`\n"
        "`/analyze_email test@example.com`"
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
    app.add_handler(CommandHandler("analyze_email", analyze_email))

    print("🤖 Bot đang chạy...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
