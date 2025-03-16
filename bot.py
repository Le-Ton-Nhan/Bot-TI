import logging
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext

# Cấu hình bot
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"

# Cấu hình logging
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)

# Hàm quét Hash trên VirusTotal
def scan_hash(update: Update, context: CallbackContext) -> None:
    if not context.args:
        update.message.reply_text("❌ Vui lòng nhập hash cần kiểm tra.")
        return

    file_hash = context.args[0]
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)
        result = response.json()

        if "data" in result:
            vt_score = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
            vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"
            update.message.reply_text(f"🔍 **VirusTotal Report:**\n- 🔴 Malicious Score: {vt_score}\n- [View Detail]({vt_link})", parse_mode="Markdown")
        else:
            update.message.reply_text("⚠️ Không tìm thấy thông tin trên VirusTotal!")

    except Exception as e:
        update.message.reply_text(f"⚠️ Lỗi khi truy vấn VirusTotal: {str(e)}")

# Hàm quét URL
def scan_url(update: Update, context: CallbackContext) -> None:
    if not context.args:
        update.message.reply_text("❌ Vui lòng nhập URL để kiểm tra.")
        return

    url = context.args[0]
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}

    try:
        response = requests.post(vt_url, headers=headers, data=data)
        result = response.json()

        if "data" in result:
            analysis_id = result["data"]["id"]
            report_url = f"https://www.virustotal.com/gui/url/{analysis_id}"
            update.message.reply_text(f"✅ URL đã gửi quét!\n🔍 Xem kết quả tại: {report_url}")

        else:
            update.message.reply_text("⚠️ Không tìm thấy thông tin trên VirusTotal!")

    except Exception as e:
        update.message.reply_text(f"⚠️ Lỗi khi quét URL: {str(e)}")

# Hàm kiểm tra email rò rỉ (ví dụ: haveibeenpwned API)
def check_email(update: Update, context: CallbackContext) -> None:
    if not context.args:
        update.message.reply_text("❌ Vui lòng nhập email để kiểm tra.")
        return

    email = context.args[0]
    hibp_api = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    try:
        response = requests.get(hibp_api)
        if response.status_code == 200:
            update.message.reply_text(f"🔴 Email {email} đã bị rò rỉ! Kiểm tra tại Have I Been Pwned.")
        else:
            update.message.reply_text(f"✅ Email {email} an toàn, không có rò rỉ dữ liệu.")
    except Exception as e:
        update.message.reply_text(f"⚠️ Lỗi khi kiểm tra email: {str(e)}")

# Hàm start
def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text("🔰 Chào mừng! Gõ /scan_hash <hash>, /scan_url <URL>, /check_email <email> để kiểm tra.")

# Khởi chạy bot
def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("scan_hash", scan_hash))
    dp.add_handler(CommandHandler("scan_url", scan_url))
    dp.add_handler(CommandHandler("check_email", check_email))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
