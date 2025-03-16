import os
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackContext

# Lấy token từ biến môi trường
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"

async def scan_hash(update: Update, context: CallbackContext):
    if not context.args:
        await update.message.reply_text("❌ Vui lòng nhập hash để kiểm tra.")
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
            await update.message.reply_text(f"🔍 **VirusTotal Report:**\n- 🔴 Malicious Score: {vt_score}\n- [Xem chi tiết]({vt_link})", parse_mode="Markdown")
        else:
            await update.message.reply_text("⚠️ Không tìm thấy thông tin trên VirusTotal!")

    except Exception as e:
        await update.message.reply_text(f"⚠️ Lỗi khi truy vấn VirusTotal: {str(e)}")

async def start(update: Update, context: CallbackContext):
    await update.message.reply_text("🔰 Chào mừng! Gõ /scan_hash <hash> để kiểm tra hash.")

def main():
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan_hash", scan_hash))

    print("🤖 Bot đang chạy...")
    app.run_polling()

if __name__ == "__main__":
    main()
