import os
import requests
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

# Cấu hình API Keys (có thể lấy từ biến môi trường)
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"
MALWAREBAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"

# --------------------- Các hàm gọi API --------------------- #

def check_ip(ip: str):
    results = {}

    # VirusTotal: kiểm tra IP
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            vt_stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results["VirusTotal"] = f"Malicious: {vt_stats.get('malicious', 'N/A')}, Suspicious: {vt_stats.get('suspicious', 'N/A')}"
        else:
            results["VirusTotal"] = f"Error: {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {str(e)}"

    # AbuseIPDB: kiểm tra IP
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
            results["AbuseIPDB"] = f"Error: {abuse_resp.status_code}"
    except Exception as e:
        results["AbuseIPDB"] = f"Exception: {str(e)}"

    # IBM X-Force: kiểm tra IP (sử dụng Basic Auth)
    try:
        xforce_url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
        auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
        xforce_resp = requests.get(xforce_url, auth=auth)
        if xforce_resp.status_code == 200:
            xforce_json = xforce_resp.json()
            xforce_score = xforce_json.get("score", "N/A")
            results["IBM X-Force"] = f"Score: {xforce_score}"
        else:
            results["IBM X-Force"] = f"Error: {xforce_resp.status_code}"
    except Exception as e:
        results["IBM X-Force"] = f"Exception: {str(e)}"

    return results

def check_url(url: str):
    results = {}

    # VirusTotal: kiểm tra URL (gửi URL để quét, trả về analysis ID)
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
            results["VirusTotal"] = f"Error: {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {str(e)}"

    # IBM X-Force: kiểm tra URL
    try:
        xforce_url = f"https://api.xforce.ibmcloud.com/url/{url}"
        auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
        xforce_resp = requests.get(xforce_url, auth=auth)
        if xforce_resp.status_code == 200:
            xforce_json = xforce_resp.json()
            xforce_score = xforce_json.get("score", "N/A")
            results["IBM X-Force"] = f"Score: {xforce_score}"
        else:
            results["IBM X-Force"] = f"Error: {xforce_resp.status_code}"
    except Exception as e:
        results["IBM X-Force"] = f"Exception: {str(e)}"

    return results

def check_domain(domain: str):
    results = {}

    # VirusTotal: kiểm tra Domain
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            vt_stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results["VirusTotal"] = f"Malicious: {vt_stats.get('malicious', 'N/A')}, Suspicious: {vt_stats.get('suspicious', 'N/A')}"
        else:
            results["VirusTotal"] = f"Error: {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {str(e)}"

    return results

def check_hash(file_hash: str):
    results = {}

    # VirusTotal: kiểm tra file hash
    try:
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            vt_stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results["VirusTotal"] = f"Malicious: {vt_stats.get('malicious', 'N/A')}, Suspicious: {vt_stats.get('suspicious', 'N/A')}"
        else:
            results["VirusTotal"] = f"Error: {vt_resp.status_code}"
    except Exception as e:
        results["VirusTotal"] = f"Exception: {str(e)}"

    # MalwareBazaar: kiểm tra file hash
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
            results["MalwareBazaar"] = f"Error: {mb_resp.status_code}"
    except Exception as e:
        results["MalwareBazaar"] = f"Exception: {str(e)}"

    return results

# --------------------- Telegram Handlers --------------------- #

# Hiển thị menu chính
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔍 Phân tích IP", callback_data="analyze_ip")],
        [InlineKeyboardButton("🔹 Kiểm tra URL", callback_data="analyze_url")],
        [InlineKeyboardButton("🔍 Lấy thông tin Domain", callback_data="analyze_domain")],
        [InlineKeyboardButton("🦠 Phân tích Hash", callback_data="analyze_hash")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Chọn chức năng cần kiểm tra:", reply_markup=reply_markup)

# Xử lý khi người dùng bấm nút trên menu
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    action = query.data
    context.user_data["action"] = action
    await query.message.reply_text(f"Bạn đã chọn: {action}\nHãy gửi lệnh:\n/analyze <dữ liệu>\nVí dụ: /analyze 8.8.8.8")

# Lệnh chung để phân tích dữ liệu
async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "action" not in context.user_data:
        await update.message.reply_text("❌ Vui lòng chọn chức năng từ menu bằng lệnh /start.")
        return
    if not context.args:
        await update.message.reply_text("❌ Vui lòng nhập dữ liệu cần kiểm tra.")
        return

    value = context.args[0]
    action = context.user_data["action"]
    result_text = ""

    if action == "analyze_ip":
        results = check_ip(value)
        result_text += f"🔍 **Phân tích IP: {value}**\n"
        for service, res in results.items():
            result_text += f"- **{service}:** {res}\n"

    elif action == "analyze_url":
        results = check_url(value)
        result_text += f"🔹 **Phân tích URL: {value}**\n"
        for service, res in results.items():
            result_text += f"- **{service}:** {res}\n"

    elif action == "analyze_domain":
        results = check_domain(value)
        result_text += f"🔍 **Phân tích Domain: {value}**\n"
        for service, res in results.items():
            result_text += f"- **{service}:** {res}\n"

    elif action == "analyze_hash":
        results = check_hash(value)
        result_text += f"🦠 **Phân tích Hash: {value}**\n"
        for service, res in results.items():
            result_text += f"- **{service}:** {res}\n"
    else:
        result_text = "❌ Chức năng không được hỗ trợ."

    await update.message.reply_text(result_text, parse_mode="Markdown")

# --------------------- Xây dựng Application --------------------- #

app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start_command))
app.add_handler(CallbackQueryHandler(button_handler))
app.add_handler(CommandHandler("analyze", analyze_command))

print("🤖 Bot đang chạy...")
app.run_polling(drop_pending_updates=True)
