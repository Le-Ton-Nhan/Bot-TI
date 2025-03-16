import os
import requests
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

# Setup logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

# API KEYS (Set environment variables)
VIRUSTOTAL_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IPQUALITY_API_KEY = "n4IFLrRkwD0tPTlJiiZGJC2lZtms8mIR"
TELEGRAM_BOT_TOKEN = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"

# Define main menu
def start(update: Update, context) -> None:
    keyboard = [[InlineKeyboardButton("Phân tích thông tin IP", callback_data="analyze_ip")],
                [InlineKeyboardButton("Kiểm tra thông tin URL", callback_data="analyze_url")],
                [InlineKeyboardButton("Lấy thông tin domain", callback_data="analyze_domain")],
                [InlineKeyboardButton("Phân tích hash file", callback_data="analyze_hash")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text('Chọn chức năng:', reply_markup=reply_markup)

def analyze_ip(update: Update, context) -> None:
    query = update.callback_query
    query.answer()
    query.message.reply_text("Vui lòng nhập IP cần phân tích.")
    context.user_data['awaiting_ip'] = True

def handle_message(update: Update, context) -> None:
    if context.user_data.get('awaiting_ip'):
        ip = update.message.text.strip()
        report = get_ip_analysis_report(ip)
        update.message.reply_text(report, disable_web_page_preview=True, parse_mode="MarkdownV2")
        context.user_data['awaiting_ip'] = False

def get_ip_analysis_report(ip: str) -> str:
    try:
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
                f"IP: `{ip}`\n"
                f"🌐 *VirusTotal:* {vt_score} / 100 🔴 - [Xem chi tiết]({vt_link})\n"
                f"🚨 *AbuseIPDB:* {abuse_score} / 100 ⚠️ - [Xem chi tiết]({abuse_link})\n"
                f"⚡ *IPQualityScore:* {fraud_score} / 100 🛑 - [Xem chi tiết]({ipquality_link})")
    except Exception as e:
        logging.error(f"Lỗi khi lấy dữ liệu IP: {e}")
        return "❌ Lỗi khi phân tích IP. Vui lòng thử lại sau."

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(analyze_ip, pattern="^analyze_ip$"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.run_polling()

if __name__ == "__main__":
    main()
