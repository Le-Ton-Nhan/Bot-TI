import os
import logging
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackContext

# Setup logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

# API KEYS (Set environment variables)
VIRUSTOTAL_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IPQUALITY_API_KEY = "n4IFLrRkwD0tPTlJiiZGJC2lZtms8mIR"
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"

# Define main menu
async def start(update: Update, context: CallbackContext) -> None:
    keyboard = [
        [InlineKeyboardButton("Phân tích thông tin IP", callback_data="analyze_ip")],
        [InlineKeyboardButton("Kiểm tra thông tin URL", callback_data="analyze_url")],
        [InlineKeyboardButton("Lấy thông tin domain", callback_data="analyze_domain")],
        [InlineKeyboardButton("Phân tích hash file", callback_data="analyze_hash")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text('Chọn chức năng:', reply_markup=reply_markup)

async def analyze_ip(update: Update, context: CallbackContext) -> None:
    if not context.args:
        await update.message.reply_text("Vui lòng nhập IP cần phân tích. Ví dụ: /analyze_ip 45.26.143.221")
        return
    ip = context.args[0]
    report = await get_ip_analysis_report(ip)
    await update.message.reply_text(report, disable_web_page_preview=True)

async def get_ip_analysis_report(ip: str) -> str:
    headers_vt = {"x-apikey": VIRUSTOTAL_API_KEY}
    headers_abuse = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    headers_ipquality = {"Content-Type": "application/json"}

    # VirusTotal Check
    vt_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers_vt).json()
    vt_score = vt_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"

    # AbuseIPDB Check
    abuse_response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers_abuse).json()
    abuse_score = abuse_response.get("data", {}).get("abuseConfidenceScore", 0)
    abuse_link = f"https://www.abuseipdb.com/check/{ip}"

    # IPQualityScore Check
    ipquality_response = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITY_API_KEY}/{ip}", headers=headers_ipquality).json()
    fraud_score = ipquality_response.get("fraud_score", 0)
    ipquality_link = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"

    return (f"🔍 *Báo Cáo Phân Tích IP*\n"
            f"IP: `{ip}`\n\n"
            f"🌐 *VirusTotal:* {vt_score} / 100 🔴 - [Xem chi tiết]({vt_link})\n"
            f"🚨 *AbuseIPDB:* {abuse_score} / 100 ⚠️ - [Xem chi tiết]({abuse_link})\n"
            f"⚡ *IPQualityScore:* {fraud_score} / 100 🛑 - [Xem chi tiết]({ipquality_link})")

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("analyze_ip", analyze_ip))

    application.run_polling()

if __name__ == "__main__":
    main()
