import os
import re
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackContext

# Lấy API keys từ biến môi trường
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"

# Xác định loại dữ liệu (IP, URL, Hash, Email, Domain)
def detect_input_type(value):
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    url_pattern = r"^(http|https)://"
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    hash_pattern = r"^[a-fA-F0-9]{32,64}$"
    
    if re.match(ip_pattern, value):
        return "ip"
    elif re.match(url_pattern, value):
        return "url"
    elif re.match(email_pattern, value):
        return "email"
    elif re.match(hash_pattern, value):
        return "hash"
    else:
        return "domain"

# Hàm kiểm tra VirusTotal
def check_virustotal(query, data_type):
    url = f"https://www.virustotal.com/api/v3/{data_type}s/{query}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        vt_score = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        vt_link = f"https://www.virustotal.com/gui/{data_type}/{query}"
        return f"🔍 **VirusTotal:**\n- 🔴 Malicious Score: {vt_score}\n- [Xem chi tiết]({vt_link})"
    return "⚠️ Không tìm thấy trên VirusTotal"

# Hàm kiểm tra IBM X-Force Exchange
def check_ibm(query, data_type):
    ibm_url = f"https://exchange.xforce.ibmcloud.com/{data_type}/{query}"
    return f"🔹 **IBM X-Force:**\n- [Xem chi tiết]({ibm_url})"

# Hàm kiểm tra MalwareBazaar (chỉ dành cho hash)
def check_malwarebazaar(query):
    bazaar_url = f"https://bazaar.abuse.ch/sample/{query}"
    return f"🦠 **MalwareBazaar:**\n- [Xem chi tiết]({bazaar_url})"

# Hàm kiểm tra IP trên AbuseIPDB
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {"ipAddress": ip}
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        result = response.json()
        abuse_score = result["data"]["abuseConfidenceScore"]
        abuse_link = f"https://www.abuseipdb.com/check/{ip}"
        return f"🛡️ **AbuseIPDB:**\n- 🔴 Abuse Score: {abuse_score}\n- [Xem chi tiết]({abuse_link})"
    return "⚠️ Không tìm thấy trên AbuseIPDB"

# Xử lý lệnh /check <value>
async def check(update: Update, context: CallbackContext):
    if not context.args:
        await update.message.reply_text("❌ Vui lòng nhập dữ liệu cần kiểm tra.\nVí dụ: `/check 8.8.8.8`")
        return

    query = context.args[0]
    data_type = detect_input_type(query)

    results = []
    
    # Kiểm tra trên VirusTotal
    results.append(check_virustotal(query, data_type))

    # Kiểm tra trên IBM X-Force
    results.append(check_ibm(query, data_type))

    # Kiểm tra trên MalwareBazaar (nếu là hash)
    if data_type == "hash":
        results.append(check_malwarebazaar(query))

    # Kiểm tra trên AbuseIPDB (nếu là IP)
    if data_type == "ip":
        results.append(check_abuseipdb(query))

    # Gửi kết quả về Telegram
    await update.message.reply_text("\n\n".join(results), parse_mode="Markdown")

# Hàm chính khởi chạy bot
def main():
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("check", check))

    print("🤖 Bot đang chạy...")
    app.run_polling()

if __name__ == "__main__":
    main()
