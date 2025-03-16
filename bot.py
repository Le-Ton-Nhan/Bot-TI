import os
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackContext

# Thay thế bằng API Key của bạn
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"

# Hàm tạo menu lệnh
def start(update: Update, context: CallbackContext) -> None:
    keyboard = [
        [InlineKeyboardButton("🔍 Phân tích IP", callback_data='analyze_ip')],
        [InlineKeyboardButton("🔹 Kiểm tra URL", callback_data='analyze_url')],
        [InlineKeyboardButton("🔍 Lấy thông tin domain", callback_data='analyze_domain')],
        [InlineKeyboardButton("🦠 Phân tích hash file", callback_data='analyze_hash')],
        [InlineKeyboardButton("📧 Kiểm tra email", callback_data='analyze_email')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text('Chọn một hành động:', reply_markup=reply_markup)

# Hàm gửi request đến VirusTotal
def check_virustotal(value: str, value_type: str):
    url = f"https://www.virustotal.com/api/v3/{value_type}/{value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Hàm kiểm tra IP với AbuseIPDB
def check_abuseipdb(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

# Hàm phân tích IP
def analyze_ip(update: Update, context: CallbackContext) -> None:
    ip = context.args[0] if context.args else None
    if not ip:
        update.message.reply_text("Vui lòng nhập IP cần kiểm tra.")
        return
    
    vt_result = check_virustotal(ip, "ip_addresses")
    abuse_result = check_abuseipdb(ip)
    
    result_text = f"🔍 **Kết quả phân tích IP {ip}:**\n"
    result_text += f"- VirusTotal: {vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})}\n"
    result_text += f"- AbuseIPDB: {abuse_result.get('data', {}).get('abuseConfidenceScore', 'N/A')}% nguy cơ"
    
    update.message.reply_text(result_text, parse_mode='Markdown')

# Khởi tạo bot
app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("analyze_ip", analyze_ip))

# Chạy bot
print("Bot đang chạy...")
app.run_polling()
