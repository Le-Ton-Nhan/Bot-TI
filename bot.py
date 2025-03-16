import os
import requests
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Application, CommandHandler, CallbackContext, CallbackQueryHandler

# Lấy API keys từ biến môi trường
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"

# Hàm kiểm tra thông tin trên VirusTotal
async def check_virustotal(update: Update, context: CallbackContext, query: str):
    url = f"https://www.virustotal.com/api/v3/{query}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    result = response.json()

    if "data" in result:
        vt_score = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        vt_link = f"https://www.virustotal.com/gui/{query}"
        await update.message.reply_text(f"🔍 **VirusTotal Report:**\n- 🔴 Malicious Score: {vt_score}\n- [Xem chi tiết]({vt_link})", parse_mode="Markdown")
    else:
        await update.message.reply_text("⚠️ Không tìm thấy thông tin trên VirusTotal!")

# Hàm kiểm tra trên IBM X-Force
async def check_ibm(update: Update, context: CallbackContext, query: str):
    ibm_url = f"https://exchange.xforce.ibmcloud.com/{query}"
    await update.message.reply_text(f"🔹 **IBM X-Force Report:**\n- [Xem chi tiết]({ibm_url})", parse_mode="Markdown")

# Hàm kiểm tra trên MalwareBazaar
async def check_malwarebazaar(update: Update, context: CallbackContext, query: str):
    bazaar_url = f"https://bazaar.abuse.ch/sample/{query}"
    await update.message.reply_text(f"🦠 **MalwareBazaar Report:**\n- [Xem chi tiết]({bazaar_url})", parse_mode="Markdown")

# Hàm kiểm tra IP trên AbuseIPDB
async def check_abuseipdb(update: Update, context: CallbackContext, ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {"ipAddress": ip}
    response = requests.get(url, headers=headers, params=params)
    result = response.json()

    if "data" in result:
        abuse_score = result["data"]["abuseConfidenceScore"]
        abuse_link = f"https://www.abuseipdb.com/check/{ip}"
        await update.message.reply_text(f"🛡️ **AbuseIPDB Report:**\n- 🔴 Abuse Score: {abuse_score}\n- [Xem chi tiết]({abuse_link})", parse_mode="Markdown")
    else:
        await update.message.reply_text("⚠️ Không tìm thấy thông tin trên AbuseIPDB!")

# Hàm gửi menu chọn dịch vụ
async def start(update: Update, context: CallbackContext):
    keyboard = [
        [InlineKeyboardButton("🔍 VirusTotal", callback_data="virustotal")],
        [InlineKeyboardButton("🔹 IBM X-Force", callback_data="ibm")],
        [InlineKeyboardButton("🦠 MalwareBazaar", callback_data="malwarebazaar")],
        [InlineKeyboardButton("🛡️ AbuseIPDB (IP Only)", callback_data="abuseipdb")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🔰 **Chọn dịch vụ kiểm tra:**", reply_markup=reply_markup)

# Xử lý khi người dùng chọn dịch vụ
async def button_click(update: Update, context: CallbackContext):
    query = update.callback_query
    await query.answer()
    context.user_data["service"] = query.data
    await query.edit_message_text(f"🔍 **Bạn đã chọn:** {query.data.upper()}\n\nGõ `/check <dữ liệu>` để kiểm tra!")

# Xử lý lệnh check
async def check(update: Update, context: CallbackContext):
    if not context.args:
        await update.message.reply_text("❌ Vui lòng nhập dữ liệu cần kiểm tra.\nVí dụ: `/check 8.8.8.8`")
        return

    query = context.args[0]
    service = context.user_data.get("service", "virustotal")  # Mặc định là VT nếu chưa chọn

    if service == "virustotal":
        await check_virustotal(update, context, f"files/{query}")  # Có thể thay bằng "domains", "urls"
    elif service == "ibm":
        await check_ibm(update, context, f"malware/{query}")
    elif service == "malwarebazaar":
        await check_malwarebazaar(update, context, query)
    elif service == "abuseipdb":
        await check_abuseipdb(update, context, query)
    else:
        await update.message.reply_text("⚠️ Không tìm thấy dịch vụ đã chọn!")

# Hàm chính khởi chạy bot
def main():
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_handler(CommandHandler("check", check))

    print("🤖 Bot đang chạy...")
    app.run_polling()

if __name__ == "__main__":
    main()
