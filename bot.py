import logging
import requests
import base64
import re
import asyncio

from telegram import Update, BotCommand
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

# ====== ĐIỀN API KEY CHO CÁC DỊCH VỤ DƯỚI ĐÂY ======
VT_API_KEY = "82a372fe87203a77e09b2e2b1ee6602d35080ca6a6247cccfb9bfaa6ae30c6a0"
ABUSEIPDB_API_KEY = "9ad9622a23685e17cb847ae9a0a11548f758dad80d761422e79dd0ab0b5cfd345be0308829ead6b5"
IBM_XFORCE_API_KEY = "41a9d14f-eb40-4402-b3ed-bcd88f5ac15e"
IBM_XFORCE_PASSWORD = "ec784682-e98d-4575-b48b-536e9d5c094f"
MALWARE_BAZAAR_API_KEY = "3fa505986c79223ae986f72890bef05fb77a1b8e64c3ac8f"
IPQUALITY_API_KEY = "n4IFLrRkwD0tPTlJiiZGJC2lZtms8mIR"
# ==================================================

# Cấu hình logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------------
#                               CÁC HÀM PHÂN TÍCH
# ------------------------------------------------------------------------------------

def analyze_ip(ip: str) -> str:
    """
    Gọi các API để phân tích IP và trả về báo cáo dạng Markdown.
    Sử dụng: VirusTotal, AbuseIPDB, IPQualityScore, IBM X-Force Exchange.
    """
    # VirusTotal - IP
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_headers = {"x-apikey": VT_API_KEY}
    try:
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_data = vt_resp.json()
            vt_attr = vt_data.get("data", {}).get("attributes", {})
            vt_stats = vt_attr.get("last_analysis_stats", {})
            vt_malicious = vt_stats.get("malicious", 0)
            vt_suspicious = vt_stats.get("suspicious", 0)
            community_score = f"{vt_malicious}/{vt_malicious + vt_suspicious}" if (vt_malicious + vt_suspicious) else "0"
        else:
            community_score = "N/A"
    except Exception as e:
        logger.error(f"VirusTotal IP error: {e}")
        community_score = "N/A"

    # AbuseIPDB
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_params = {"ipAddress": ip, "maxAgeInDays": 90}
    abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        abuse_resp = requests.get(abuse_url, headers=abuse_headers, params=abuse_params)
        if abuse_resp.status_code == 200:
            abuse_data = abuse_resp.json()
            abuse_confidence = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)
        else:
            abuse_confidence = "N/A"
    except Exception as e:
        logger.error(f"AbuseIPDB error: {e}")
        abuse_confidence = "N/A"

    # IPQualityScore
    ipq_url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITY_API_KEY}/{ip}"
    try:
        ipq_resp = requests.get(ipq_url)
        if ipq_resp.status_code == 200:
            ipq_data = ipq_resp.json()
            isp = ipq_data.get("isp", "N/A")
            country = ipq_data.get("country_code", "N/A")
            proxy = ipq_data.get("proxy", False)
            vpn = ipq_data.get("vpn", False)
            tor = ipq_data.get("tor", False)
            fraud_score = ipq_data.get("fraud_score", "N/A")
            org = ipq_data.get("organization", "N/A")
            domain = ipq_data.get("host", "N/A")
            connection_type = ipq_data.get("connection_type", "N/A")
        else:
            isp = country = proxy = vpn = tor = fraud_score = org = domain = connection_type = "N/A"
    except Exception as e:
        logger.error(f"IPQualityScore error: {e}")
        isp = country = proxy = vpn = tor = fraud_score = org = domain = connection_type = "N/A"

    # IBM X-Force Exchange (tùy chọn)
    ibm_url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
    try:
        ibm_resp = requests.get(ibm_url, auth=(IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD))
        if ibm_resp.status_code == 200:
            ibm_data = ibm_resp.json()
            ibm_score = ibm_data.get("score", "N/A")
        elif ibm_resp.status_code == 403:
            ibm_score = "Hết free"
        else:
            ibm_score = "N/A"
    except Exception as e:
        logger.error(f"IBM X-Force IP error: {e}")
        ibm_score = "N/A"

    report = (
        f"*Báo Cáo Phân Tích IP*\n"
        f"IP: `{ip}`\n"
        f"ISP: {isp}\n"
        f"Domain: {domain}\n"
        f"Hostname: N/A\n"
        f"Country: {country}\n"
        f"Type: {connection_type}\n"
        f"Proxy: {proxy} | VPN: {vpn} | Tor: {tor}\n"
        f"Org: {org}\n\n"
        f"*VirusTotal:* Community Score: {community_score} {'🟢' if community_score in ['0', '0/0'] else '🔴'} "
        f"- [View Detail](https://www.virustotal.com/gui/ip-address/{ip})\n"
        f"*AbuseIPDB:* Confidence Score: {abuse_confidence}% {'🟢' if str(abuse_confidence) in ['0', 'N/A'] else '🔴'} "
        f"- [View Detail](https://www.abuseipdb.com/check/{ip})\n"
        f"*IPQualityScore:* Fraud Score: {fraud_score}% {'🟢' if isinstance(fraud_score, int) and fraud_score < 70 else '🔴'} "
        f"- [View Detail](https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip})\n"
        f"*IBM X-Force:* {ibm_score} - [View Detail](https://exchange.xforce.ibmcloud.com/ip/{ip})\n"
    )
    return report


def analyze_url(url: str) -> str:
    """
    Phân tích URL qua VirusTotal, IPQualityScore, IBM X-Force Exchange.
    """
    # VirusTotal yêu cầu URL được mã hoá base64 (không padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    vt_headers = {"x-apikey": VT_API_KEY}
    try:
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_data = vt_resp.json()
            vt_attr = vt_data.get("data", {}).get("attributes", {})
            vt_stats = vt_attr.get("last_analysis_stats", {})
            malicious = vt_stats.get("malicious", 0)
            total = sum(vt_stats.values())
            vt_score = f"{malicious}/{total}" if total else "0"
        else:
            vt_score = "N/A"
    except Exception as e:
        logger.error(f"VirusTotal URL error: {e}")
        vt_score = "N/A"

    # IBM X-Force Exchange - URL
    ibm_url = f"https://api.xforce.ibmcloud.com/url/{url}"
    try:
        ibm_resp = requests.get(ibm_url, auth=(IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD))
        if ibm_resp.status_code == 200:
            ibm_data = ibm_resp.json()
            ibm_score = ibm_data.get("result", {}).get("score", "N/A")
        elif ibm_resp.status_code == 403:
            ibm_score = "Hết free"
        else:
            ibm_score = "N/A"
    except Exception as e:
        logger.error(f"IBM X-Force URL error: {e}")
        ibm_score = "N/A"

    # IPQualityScore - URL (demo link)
    ipq_link = f"https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner/{url}"

    report = (
        f"*Báo Cáo Phân Tích URL*\n"
        f"URL: `{url}`\n\n"
        f"*VirusTotal:* Community Score: {vt_score} {'🔴' if vt_score not in ['0', '0/0', 'N/A'] else '🟢'} "
        f"- [View Detail](https://www.virustotal.com/gui/url/{url_id})\n"
        f"*IBM X-Force Exchange:* {ibm_score} - [View Detail](https://exchange.xforce.ibmcloud.com/url/{url})\n"
        f"*IPQualityScore:* - [View Detail]({ipq_link})\n"
    )
    return report


def analyze_domain(domain: str) -> str:
    """
    Phân tích domain qua VirusTotal, IBM X-Force Exchange, IPQualityScore.
    """
    # VirusTotal - Domain
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    vt_headers = {"x-apikey": VT_API_KEY}
    try:
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_data = vt_resp.json()
            vt_attr = vt_data.get("data", {}).get("attributes", {})
            vt_stats = vt_attr.get("last_analysis_stats", {})
            malicious = vt_stats.get("malicious", 0)
            total = sum(vt_stats.values())
            vt_score = f"{malicious}/{total}" if total else "0"
        else:
            vt_score = "N/A"
    except Exception as e:
        logger.error(f"VirusTotal domain error: {e}")
        vt_score = "N/A"

    # IBM X-Force Exchange - Domain
    ibm_url = f"https://api.xforce.ibmcloud.com/url/{domain}"
    try:
        ibm_resp = requests.get(ibm_url, auth=(IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD))
        if ibm_resp.status_code == 200:
            ibm_data = ibm_resp.json()
            ibm_score = ibm_data.get("result", {}).get("score", "N/A")
        elif ibm_resp.status_code == 403:
            ibm_score = "Hết free"
        else:
            ibm_score = "N/A"
    except Exception as e:
        logger.error(f"IBM X-Force domain error: {e}")
        ibm_score = "N/A"

    # IPQualityScore - Domain (demo link)
    ipq_link = f"https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner/{domain}"

    report = (
        f"*Báo Cáo Phân Tích Domain*\n"
        f"Domain: `{domain}`\n\n"
        f"*VirusTotal:* Community Score: {vt_score} {'🔴' if vt_score not in ['0', '0/0', 'N/A'] else '🟢'} "
        f"- [View Detail](https://www.virustotal.com/gui/domain/{domain})\n"
        f"*IBM X-Force Exchange:* {ibm_score} - [View Detail](https://exchange.xforce.ibmcloud.com/url/{domain})\n"
        f"*IPQualityScore:* - [View Detail]({ipq_link})\n"
    )
    return report


def analyze_hash(file_hash: str) -> str:
    """
    Phân tích hash (MD5/SHA1/SHA256) qua VirusTotal, MalwareBazaar, IBM X-Force Exchange.
    """
    # VirusTotal - file hash
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    vt_headers = {"x-apikey": VT_API_KEY}
    try:
        vt_resp = requests.get(vt_url, headers=vt_headers)
        if vt_resp.status_code == 200:
            vt_data = vt_resp.json()
            vt_attr = vt_data.get("data", {}).get("attributes", {})
            vt_stats = vt_attr.get("last_analysis_stats", {})
            malicious = vt_stats.get("malicious", 0)
            total = sum(vt_stats.values())
            vt_score = f"{malicious}/{total}" if total else "0"
        else:
            vt_score = "N/A"
    except Exception as e:
        logger.error(f"VirusTotal hash error: {e}")
        vt_score = "N/A"

    # MalwareBazaar
    mb_url = "https://mb-api.abuse.ch/api/v1/"
    mb_data = {"query": "get_info", "hash": file_hash}
    mb_headers = {"API-KEY": MALWARE_BAZAAR_API_KEY} if MALWARE_BAZAAR_API_KEY else {}
    try:
        mb_resp = requests.post(mb_url, data=mb_data, headers=mb_headers)
        if mb_resp.status_code == 200:
            mb_json = mb_resp.json()
            mb_query_status = mb_json.get("query_status", "N/A")
        else:
            mb_query_status = "N/A"
    except Exception as e:
        logger.error(f"MalwareBazaar error: {e}")
        mb_query_status = "N/A"

    # IBM X-Force Exchange - hash
    ibm_url = f"https://api.xforce.ibmcloud.com/malware/{file_hash}"
    try:
        ibm_resp = requests.get(ibm_url, auth=(IBM_XFORCE_API_KEY, IBM_XFORCE_PASSWORD))
        if ibm_resp.status_code == 200:
            ibm_data = ibm_resp.json()
            ibm_malware_family = ibm_data.get("family", "N/A")
        elif ibm_resp.status_code == 403:
            ibm_malware_family = "Hết free"
        else:
            ibm_malware_family = "N/A"
    except Exception as e:
        logger.error(f"IBM X-Force hash error: {e}")
        ibm_malware_family = "N/A"

    report = (
        f"*Báo Cáo Phân Tích Hash*\n"
        f"Hash: `{file_hash}`\n\n"
        f"*VirusTotal:* Detection: {vt_score} {'🔴' if vt_score not in ['0', '0/0', 'N/A'] else '🟢'} "
        f"- [View Detail](https://www.virustotal.com/gui/file/{file_hash})\n"
        f"*MalwareBazaar:* Trạng thái: {mb_query_status}\n"
        f"*IBM X-Force Exchange:* Malware Family: {ibm_malware_family} - [View Detail](https://exchange.xforce.ibmcloud.com/malware/{file_hash})\n"
    )
    return report


def analyze_email(email: str) -> str:
    """
    Demo phân tích email.
    """
    report = (
        f"*Báo Cáo Phân Tích Email*\n"
        f"Email: `{email}`\n\n"
        f"Hiện tại chưa tích hợp dịch vụ phân tích email cụ thể.\n"
        f"Vui lòng tích hợp thêm EmailRep.io hoặc công cụ khác nếu cần.\n"
    )
    return report

# ------------------------------------------------------------------------------------
#                               CÁC HÀM XỬ LÝ LỆNH
# ------------------------------------------------------------------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /start: Chào mừng."""
    await update.message.reply_text(
        "Chào bạn! Hãy dùng các lệnh sau để phân tích:\n"
        "/analyze_ip <IP>\n"
        "/analyze_url <URL>\n"
        "/analyze_domain <domain>\n"
        "/analyze_hash <file_hash>\n"
        "/analyze_email <email>\n"
    )

async def analyze_ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /analyze_ip <IP>."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập IP sau lệnh, ví dụ: /analyze_ip 8.8.8.8")
        return
    ip = context.args[0]
    report = analyze_ip(ip)
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def analyze_url_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /analyze_url <URL>."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập URL sau lệnh, ví dụ: /analyze_url google.com")
        return
    url = context.args[0]
    report = analyze_url(url)
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def analyze_domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /analyze_domain <domain>."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập domain sau lệnh, ví dụ: /analyze_domain example.com")
        return
    domain = context.args[0]
    report = analyze_domain(domain)
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def analyze_hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /analyze_hash <file_hash>."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập hash sau lệnh, ví dụ: /analyze_hash 44d88612fea8a8f36de82e1278abb02f")
        return
    file_hash = context.args[0]
    report = analyze_hash(file_hash)
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def analyze_email_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Lệnh /analyze_email <email>."""
    if not context.args:
        await update.message.reply_text("Vui lòng nhập email sau lệnh, ví dụ: /analyze_email someone@example.com")
        return
    email = context.args[0]
    report = analyze_email(email)
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

# ------------------------------------------------------------------------------------
#                               HÀM CHẠY CHÍNH
# ------------------------------------------------------------------------------------

async def main():
    # Thay token bot của bạn
    bot_token = "7923484184:AAHmqEl9yCUd4TNOlWZfyhlWz6bJbl7e0pg"
    application = ApplicationBuilder().token(bot_token).build()

    # Đăng ký handler cho các lệnh
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("analyze_ip", analyze_ip_command))
    application.add_handler(CommandHandler("analyze_url", analyze_url_command))
    application.add_handler(CommandHandler("analyze_domain", analyze_domain_command))
    application.add_handler(CommandHandler("analyze_hash", analyze_hash_command))
    application.add_handler(CommandHandler("analyze_email", analyze_email_command))

    # Đặt menu lệnh (hiển thị khi gõ '/')
    await application.bot.set_my_commands([
        BotCommand("start", "Bắt đầu"),
        BotCommand("analyze_ip", "Phân tích thông tin IP"),
        BotCommand("analyze_url", "Kiểm tra thông tin URL"),
        BotCommand("analyze_domain", "Lấy thông tin domain"),
        BotCommand("analyze_hash", "Phân tích hash file"),
        BotCommand("analyze_email", "Kiểm tra email")
    ])

    # Chạy polling mà không đóng event loop
    await application.run_polling(close_loop=False)

if __name__ == "__main__":
    try:
        import nest_asyncio
        nest_asyncio.apply()
    except ImportError:
        pass
    asyncio.run(main())
