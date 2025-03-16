import os
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

# Cấu hình API Keys
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"
MALWAREBAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"

# Menu chính của bot
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔍 Phân tích IP", callback_data='analyze_ip')],
        [InlineKeyboardButton("🔹 Kiểm tra URL", callback_data='analyze_url')],
        [InlineKeyboardButton("🔍 Lấy thông tin domain", callback_data='analyze_domain')],
        [InlineKeyboardButton("🦠 Phân tích hash file", callback_data='analyze_hash')],
        [InlineKeyboardButton("📧 Kiểm tra email", callback_data='analyze_email')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text('🔹 Chọn một hành động:', reply_markup=reply_markup)

# Xử lý chọn menu
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(f"Vui lòng nhập dữ liệu cần kiểm tra ({query.data}):")

# Kiểm tra IP bằng VirusTotal & AbuseIPDB
def check_ip(ip: str):
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    vt_response = requests.get(vt_url, headers=vt_headers).json()

    # AbuseIPDB
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_params = {"ipAddress": ip, "maxAgeInDays": 90}
    abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    abuse_response = requests.get(abuse_url, headers=abuse_headers, params=abuse_params).json()

    return vt_response, abuse_response

# Kiểm tra URL bằng VirusTotal & IBM X-Force
def check_url(url: str):
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/urls"
    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    vt_data = {"url": url}
    vt_response = requests.post(vt_url, headers=vt_headers, data=vt_data).json()

    # IBM X-Force
    ibm_url = f"https://api.xforce.ibmcloud.com/url/{url}"
    ibm_auth = (IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD)
    ibm_response = requests.get(ibm_url, auth=ibm_auth).json()

    return vt_response, ibm_response

# Kiểm tra hash file trên MalwareBazaar
def check_hash(file_hash: str):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    response = requests.post(url, data=data).json()
    return response

# Xử lý phân tích dữ liệu
async def analyze_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text.split(" ")[0]
    value = update.message.text.split(" ")[1] if len(update.message.text.split(" ")) > 1 else None

    if not value:
        await update.message.reply_text("❌ Vui lòng nhập dữ liệu hợp lệ.")
        return

    if command == "/analyze_ip":
        vt_result, abuse_result = check_ip(value)
        text = f"🔍 **Phân tích IP: {value}**\n"
        text += f"- **VirusTotal:** {vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})}\n"
        text += f"- **AbuseIPDB:** {abuse_result.get('data', {}).get('abuseConfidenceScore', 'N/A')}% nguy cơ"
        await update.message.reply_text(text, parse_mode='Markdown')

    elif command == "/analyze_url":
        vt_result, ibm_result = check_url(value)
        text = f"🔹 **Phân tích URL: {value}**\n"
        text += f"- **VirusTotal:** {vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})}\n"
        text += f"- **IBM X-Force:** {ibm_result.get('score', 'N/A')} điểm tin cậy"
        await update.message.reply_text(text, parse_mode='Markdown')

    elif command == "/analyze_hash":
        hash_result = check_hash(value)
        text = f"🦠 **Phân tích Hash: {value}**\n"
        text += f"- **MalwareBazaar:** {hash_result.get('query_status', 'Không tìm thấy')}"
        await update.message.reply_text(text, parse_mode='Markdown')

# Khởi tạo bot
app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CallbackQueryHandler(button_callback))
app.add_handler(CommandHandler(["analyze_ip", "analyze_url", "analyze_hash"], analyze_data))

# Chạy bot
print("🤖 Bot đang chạy...")
app.run_polling(drop_pending_updates=True)
