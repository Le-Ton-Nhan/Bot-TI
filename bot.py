import os
import requests
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

# ========== CẤU HÌNH API KEYS ==========

TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"
MALWAREBAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"



# ========== HÀM GỌI API ==========

def check_ip(ip: str) -> dict:
    """Kiểm tra IP bằng VirusTotal, AbuseIPDB, IBM X-Force."""
    results = {}

    # -- VirusTotal --
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            results["VirusTotal"] = f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            results["VirusTotal"] = f"Error {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {e}"

    # -- AbuseIPDB --
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        abuse_params = {"ipAddress": ip, "maxAgeInDays": 90}
        abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        abuse_resp = requests.get(abuse_url, headers=abuse_headers, params=abuse_params)
        if abuse_resp.status_code == 200:
            abuse_json = abuse_resp.json()
            abuse_score = abuse_json.get("data", {}).get("abuseConfidenceScore", "N/A")
            results["AbuseIPDB"] = f"Abuse Confidence Score: {abuse_score}%"
        else:
            results["AbuseIPDB"] = f"Error {abuse_resp.status_code}"
    except Exception as e:
        results["AbuseIPDB"] = f"Exception: {e}"

    # -- IBM X-Force --
    try:
        xforce_url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
        auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
        xforce_resp = requests.get(xforce_url, auth=auth)
        if xforce_resp.status_code == 200:
            xforce_json = xforce_resp.json()
            score = xforce_json.get("score", "N/A")
            results["IBM X-Force"] = f"Score: {score}"
        else:
            results["IBM X-Force"] = f"Error {xforce_resp.status_code}"
    except Exception as e:
        results["IBM X-Force"] = f"Exception: {e}"

    return results


def check_url(url: str) -> dict:
    """Kiểm tra URL bằng VirusTotal, IBM X-Force."""
    results = {}

    # -- VirusTotal --
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_data = {"url": url}
        vt_resp = requests.post(vt_url, headers=vt_headers, data=vt_data)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            analysis_id = vt_json.get("data", {}).get("id", "N/A")
            results["VirusTotal"] = f"Analysis ID: {analysis_id}"
        else:
            results["VirusTotal"] = f"Error {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {e}"

    # -- IBM X-Force --
    try:
        xforce_url = f"https://api.xforce.ibmcloud.com/url/{url}"
        auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
        xforce_resp = requests.get(xforce_url, auth=auth)
        if xforce_resp.status_code == 200:
            xforce_json = xforce_resp.json()
            score = xforce_json.get("score", "N/A")
            results["IBM X-Force"] = f"Score: {score}"
        else:
            results["IBM X-Force"] = f"Error {xforce_resp.status_code}"
    except Exception as e:
        results["IBM X-Force"] = f"Exception: {e}"

    return results


def check_domain(domain: str) -> dict:
    """Kiểm tra Domain bằng VirusTotal (có thể mở rộng IBM X-Force)."""
    results = {}

    # -- VirusTotal --
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            results["VirusTotal"] = f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            results["VirusTotal"] = f"Error {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {e}"

    return results


def check_hash(file_hash: str) -> dict:
    """Kiểm tra hash bằng VirusTotal & MalwareBazaar."""
    results = {}

    # -- VirusTotal --
    try:
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            results["VirusTotal"] = f"Malicious: {malicious}, Suspicious: {suspicious}"
        else:
            results["VirusTotal"] = f"Error {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {e}"

    # -- MalwareBazaar --
    try:
        mb_url = "https://mb-api.abuse.ch/api/v1/"
        mb_data = {"query": "get_info", "hash": file_hash}
        mb_headers = {"API-KEY": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY != "YOUR_MALWAREBAZAAR_API_KEY" else {}
        mb_resp = requests.post(mb_url, data=mb_data, headers=mb_headers)
        if mb_resp.status_code == 200:
            mb_json = mb_resp.json()
            if mb_json.get("query_status") == "ok":
                results["MalwareBazaar"] = "Hash found in MalwareBazaar"
            else:
                results["MalwareBazaar"] = "Hash not found in MalwareBazaar"
        else:
            results["MalwareBazaar"] = f"Error {mb_resp.status_code}"
    except Exception as e:
        results["MalwareBazaar"] = f"Exception: {e}"

    return results


# ========== CÁC HANDLER CHO TỪNG LỆNH ==========

from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

async def analyze_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập IP, ví dụ: /analyze_ip 8.8.8.8")
        return
    ip = context.args[0]
    results = check_ip(ip)
    text = f"🔍 **Phân tích IP: {ip}**\n"
    for service, detail in results.items():
        text += f"- **{service}**: {detail}\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL, ví dụ: /analyze_url https://example.com")
        return
    url = context.args[0]
    results = check_url(url)
    text = f"🔹 **Phân tích URL: {url}**\n"
    for service, detail in results.items():
        text += f"- **{service}**: {detail}\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def analyze_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập domain, ví dụ: /analyze_domain example.com")
        return
    domain = context.args[0]
    results = check_domain(domain)
    text = f"🔍 **Phân tích Domain: {domain}**\n"
    for service, detail in results.items():
        text += f"- **{service}**: {detail}\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def analyze_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash, ví dụ: /analyze_hash f5d11fe4ca22...")
        return
    file_hash = context.args[0]
    results = check_hash(file_hash)
    text = f"🦠 **Phân tích Hash: {file_hash}**\n"
    for service, detail in results.items():
        text += f"- **{service}**: {detail}\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def analyze_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Placeholder cho phân tích email (KHÔNG dùng HIBP)."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập email, ví dụ: /analyze_email test@example.com")
        return
    email = context.args[0]
    # Hiện tại không tích hợp HIBP hay dịch vụ khác
    text = (
        f"📧 **Phân tích Email: {email}**\n"
        "- **Kết quả**: Chức năng kiểm tra email chưa được tích hợp."
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "💡 **Danh sách lệnh:**\n"
        "/analyze_ip <IP> - Phân tích thông tin IP\n"
        "/analyze_url <URL> - Kiểm tra thông tin URL\n"
        "/analyze_domain <domain> - Lấy thông tin domain\n"
        "/analyze_hash <hash> - Phân tích hash file\n"
        "/analyze_email <email> - Kiểm tra email (chưa tích hợp)\n"
        "\nVí dụ:\n"
        "`/analyze_ip 8.8.8.8`\n"
        "`/analyze_url https://example.com`\n"
        "`/analyze_domain example.com`\n"
        "`/analyze_hash f5d11fe4ca22e193cb1dc4b7f6d14b31`\n"
        "`/analyze_email test@example.com`"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Xin chào! Gõ /help để xem hướng dẫn sử dụng.")


def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    # Đăng ký handler cho từng lệnh
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))

    app.add_handler(CommandHandler("analyze_ip", analyze_ip))
    app.add_handler(CommandHandler("analyze_url", analyze_url))
    app.add_handler(CommandHandler("analyze_domain", analyze_domain))
    app.add_handler(CommandHandler("analyze_hash", analyze_hash))
    app.add_handler(CommandHandler("analyze_email", analyze_email))

    print("🤖 Bot đang chạy...")
    app.run_polling()


if __name__ == "__main__":
    main()
