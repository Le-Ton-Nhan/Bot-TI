import os
import requests
import hashlib
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



# ========== HELPER FUNCTIONS ==========

def get_url_id(url: str) -> str:
    """
    Tính SHA256 của URL (không thực hiện base64) để dùng trong endpoint VT,
    ví dụ kết quả của "br-icloud.com.br" sẽ khớp với báo cáo của VT.
    """
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


def check_url_virustotal(url: str) -> str:
    """
    Gọi GET /urls/{id} với id = SHA256(url)
    và lấy thông tin last_analysis_stats để hiển thị Community Score dưới dạng malicious/undetected.
    """
    try:
        url_id = get_url_id(url)
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)
            # Tạo chuỗi theo định dạng: "Community Score: 13/94"
            return f"Community Score: {malicious}/{undetected}"
        else:
            return f"Error {vt_resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


def check_url_ipqualityscore(url: str) -> str:
    """
    Gọi API của IPQualityScore cho URL.
    Endpoint: https://www.ipqualityscore.com/api/json/url/{API_KEY}/{url}
    """
    try:
        qs_url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_API_KEY}/{url}"
        resp = requests.get(qs_url)
        if resp.status_code == 200:
            qs_json = resp.json()
            if qs_json.get("success", False):
                fraud_score = qs_json.get("fraud_score", "N/A")
                return f"Fraud Score: {fraud_score}"
            else:
                return f"Error: {qs_json.get('message', 'Unknown error')}"
        else:
            return f"Error {resp.status_code}"
    except Exception as e:
        return f"Exception: {e}"


# Các hàm phân tích IP, Domain, Hash, Email (Email là placeholder) – giữ nguyên như cũ

def check_ip_virustotal(ip: str) -> str:
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
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


def check_ip_abuseipdb(ip: str) -> str:
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


def check_domain_virustotal(domain: str) -> str:
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


def check_email_placeholder(email: str) -> str:
    return "Chức năng kiểm tra email chưa được tích hợp."


# ========== TELEGRAM HANDLERS ==========

async def analyze_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập IP, ví dụ: /analyze_ip 45.26.143.221")
        return
    ip = context.args[0]
    # Sử dụng IPQualityScore cho báo cáo chi tiết IP (giả sử API cho IP cũng tương tự)
    # Ở đây ta giữ nguyên hàm check_ip_virustotal và abuseIPDB cho IP
    vt_result = check_ip_virustotal(ip)
    abuse_result = check_ip_abuseipdb(ip)
    report = f"**Báo Cáo Phân Tích IP**\nIP: {ip}\n"
    report += f"- VirusTotal: {vt_result} 🟢 - [View Detail](https://www.virustotal.com/gui/ip-address/{ip})\n"
    report += f"- AbuseIPDB: {abuse_result} 🟢 - [View Detail](https://www.abuseipdb.com/check/{ip})"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL, ví dụ: /analyze_url br-icloud.com.br")
        return
    url = context.args[0]
    # VirusTotal
    vt_detail = check_url_virustotal(url)
    # IBM X-Force: trả về "Hết free" (vì free API không còn hỗ trợ)
    xforce_detail = "Hết free"
    # IPQualityScore cho URL
    ipqs_detail = check_url_ipqualityscore(url)
    report = f"**Báo Cáo Phân Tích URL**\nURL: {url}\n"
    report += f"- VirusTotal: {vt_detail} 🔴 - [View Detail](https://www.virustotal.com/gui/url/{get_url_id(url)})\n"
    report += f"- IBM X-Force Exchange: {xforce_detail} - [View Detail](https://exchange.xforce.ibmcloud.com/ip/{url})\n"
    report += f"- IPQualityScore: {ipqs_detail} 🔴 - [View Detail](https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner/{url})"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập domain, ví dụ: /analyze_domain example.com")
        return
    domain = context.args[0]
    vt_detail = check_domain_virustotal(domain)
    report = f"**Báo Cáo Phân Tích Domain**\nDomain: {domain}\n"
    report += f"- VirusTotal: {vt_detail} 🔴 - [View Detail](https://www.virustotal.com/gui/domain/{domain})"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash, ví dụ: /analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31")
        return
    file_hash = context.args[0]
    vt_detail = check_hash_virustotal(file_hash)
    mb_detail = check_hash_malwarebazaar(file_hash)
    report = f"**Báo Cáo Phân Tích Hash**\nHash: {file_hash}\n"
    report += f"- VirusTotal: {vt_detail} 🔴 - [View Detail](https://www.virustotal.com/gui/file/{file_hash})\n"
    report += f"- MalwareBazaar: {mb_detail}"
    await update.message.reply_text(report, parse_mode="Markdown")


async def analyze_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập email, ví dụ: /analyze_email test@example.com")
        return
    email = context.args[0]
    detail = check_email_placeholder(email)
    report = f"**Báo Cáo Phân Tích Email**\nEmail: {email}\n- {detail}"
    await update.message.reply_text(report, parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "💡 **Danh sách lệnh:**\n"
        "/analyze_ip <IP> - Phân tích thông tin IP\n"
        "/analyze_url <URL> - Phân tích thông tin URL\n"
        "/analyze_domain <domain> - Phân tích domain\n"
        "/analyze_hash <hash> - Phân tích hash file\n"
        "/analyze_email <email> - Phân tích email (placeholder)\n"
        "\nVí dụ:\n"
        "`/analyze_url br-icloud.com.br`\n"
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
    app.add_handler(CommandHandler("analyze_email", analyze_email))

    print("🤖 Bot đang chạy...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
