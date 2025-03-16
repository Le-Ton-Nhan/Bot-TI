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

    # IPQualityScore Check
    ipquality_url = f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITY_API_KEY}/{ip}"
    ipquality_response = requests.get(ipquality_url, headers=headers_ipquality).json()
    
    isp = ipquality_response.get("ISP", "N/A")
    domain = ipquality_response.get("host", "N/A")
    country = ipquality_response.get("country_code", "N/A")
    city = ipquality_response.get("city", "N/A")
    region = ipquality_response.get("region", "N/A")
    timezone = ipquality_response.get("timezone", "N/A")
    proxy = "Yes" if ipquality_response.get("proxy", False) else "No"
    vpn = "Yes" if ipquality_response.get("vpn", False) else "No"
    tor = "Yes" if ipquality_response.get("tor", False) else "No"
    org = ipquality_response.get("organization", "N/A")
    fraud_score = ipquality_response.get("fraud_score", 0)
    
    # VirusTotal Check
    vt_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers_vt).json()
    vt_score = vt_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"

    # AbuseIPDB Check
    abuse_response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers_abuse).json()
    abuse_score = abuse_response.get("data", {}).get("abuseConfidenceScore", 0)
    abuse_link = f"https://www.abuseipdb.com/check/{ip}"

    return (f"🔍 *Báo Cáo Phân Tích IP*\n"
            f"IP: `{ip}`\n"
            f"ISP: {isp}\n"
            f"Domain: {domain}\n"
            f"Country: {country}\n"
            f"City: {city}\n"
            f"Region: {region}\n"
            f"Timezone: {timezone}\n"
            f"Proxy: {proxy} | VPN: {vpn} | Tor: {tor}\n"
            f"Org: {org}\n"
            f"\n"
            f"🌐 *VirusTotal:* {vt_score} / 100 🔴 - [Xem chi tiết]({vt_link})\n"
            f"🚨 *AbuseIPDB:* {abuse_score} / 100 ⚠️ - [Xem chi tiết]({abuse_link})\n"
            f"⚡ *IPQualityScore:* {fraud_score} / 100 🛑 - [Xem chi tiết](https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip})")

# Kiểm tra URL
async def analyze_url(update: Update, context: CallbackContext) -> None:
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL. Ví dụ: /analyze_url example.com")
        return
    url = context.args[0]
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Thêm http:// nếu chỉ nhập domain
    report = await get_url_analysis_report(url)
    await update.message.reply_text(report, disable_web_page_preview=True)

async def get_url_analysis_report(url: str) -> str:
    headers_vt = {"x-apikey": VIRUSTOTAL_API_KEY}
    payload = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers_vt, data=payload).json()
    analysis_id = response.get("data", {}).get("id")
    
    if not analysis_id:
        return "❌ Không thể phân tích URL này."

    analysis_result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers_vt).json()
    malicious_count = analysis_result.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
    vt_link = f"https://www.virustotal.com/gui/url/{analysis_id}"
    
    # Kiểm tra với IPQualityScore
    clean_url = url.replace("http://", "").replace("https://", "")
    ipquality_url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITY_API_KEY}/{clean_url}"
    #ipquality_response = requests.get(ipquality_url).json()
    try:
        ipquality_response = requests.get(ipquality_url).json()
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Không thể phân tích URL. API không trả về dữ liệu hợp lệ."
    risk_score = ipquality_response.get("risk_score", 0)
    malicious = "Yes" if ipquality_response.get("malicious", False) else "No"
    phishing = "Yes" if ipquality_response.get("phishing", False) else "No"
    suspicious = "Yes" if ipquality_response.get("suspicious", False) else "No"
    ipquality_link = f"https://www.ipqualityscore.com/url-checker/result/{url}"
    
    return (f"🔍 *Báo Cáo Phân Tích URL*\n"
            f"🌐 URL: `{url}`\n"
            f"🚨 VirusTotal: {malicious_count} báo cáo độc hại 🔴 - [Xem chi tiết]({vt_link})\n"
            f"⚡ *IPQualityScore:* Risk Score: {risk_score} / 100 🛑\n"
            f"- Malicious: {malicious} | Phishing: {phishing} | Suspicious: {suspicious}\n"
            f"[Xem chi tiết]({ipquality_link})")

# Kiểm tra hash file
async def analyze_hash(update: Update, context: CallbackContext) -> None:
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash. Ví dụ: /analyze_hash d41d8cd98f00b204e9800998ecf8427e")
        return
    file_hash = context.args[0]
    report = await get_hash_analysis_report(file_hash)
    await update.message.reply_text(report, disable_web_page_preview=True)

async def get_hash_analysis_report(file_hash: str) -> str:
    headers_vt = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers_vt).json()
    stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"
    return f"🔍 *Báo Cáo Phân Tích Hash*\n📁 Hash: `{file_hash}`\n🚨 VirusTotal: {malicious_count} độc hại 🔴\n[Xem chi tiết]({vt_link})"

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("analyze_ip", analyze_ip))
    application.add_handler(CommandHandler("analyze_url", analyze_url))
    application.add_handler(CommandHandler("analyze_hash", analyze_hash))

    application.run_polling()

if __name__ == "__main__":
    main()
