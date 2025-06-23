import json
import re
import threading
from urllib.parse import urlparse
from typing import Dict, Any, Optional
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from src.script.method.ip_lookup import ip_lookup
from src.script.method.whois import whois
from src.script.method.ping import ping
from src.script.method.http import http
from src.script.method.tcp import tcp
from src.script.method.udp import udp
from src.script.method.dns import dns
from src.script.logs import logs

class CheckHost:
    def __init__(self, bot_token: str):
        self.bot = telebot.TeleBot(bot_token)
        self.ipLookupClass = ip_lookup()
        self.whoisClass = whois()
        self.pingClass = ping()
        self.httpClass = http()
        self.tcpClass = tcp()
        self.udpClass = udp()
        self.dnsClass = dns()
        self.logsClass = logs()
        self.setupHandlers()
        
    def checkHostConfigFileOpen(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open("src/check-host-config.json", "r") as f:
                return json.loads(f.read())
        except FileNotFoundError:
            return {
                "check-host": {
                    "version": "2.0",
                    "methods": {
                        "ip-lookup": "🔍 IP Lookup",
                        "whois": "📋 WHOIS Information", 
                        "ping": "📡 Ping Test",
                        "http": "🌐 HTTP Check",
                        "tcp": "🔌 TCP Connection",
                        "udp": "📤 UDP Check",
                        "dns": "🌍 DNS Lookup"
                    }
                }
            }
    
    def checkHostConfigAccess(self, func: str, attribute: str) -> Any:
        return self.checkHostConfigFileOpen()[func][attribute]
    
    def isValidIp(self, ip: str) -> bool:
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
        return bool(re.match(pattern, ip))
    
    def isValidDomain(self, domain: str) -> bool:
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*
        return bool(re.match(pattern, domain))
    
    def isValidUrl(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def extractTarget(self, text: str) -> Optional[str]:
        text = text.strip()
        
        if self.isValidUrl(text):
            parsed = urlparse(text)
            return parsed.netloc or parsed.path
        elif self.isValidDomain(text) or self.isValidIp(text):
            return text
        
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)
        if urls:
            parsed = urlparse(urls[0])
            return parsed.netloc
        
        domain_pattern = r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
        domains = re.findall(domain_pattern, text)
        if domains:
            domain = domains[0][0] if isinstance(domains[0], tuple) else domains[0]
            if self.isValidDomain(domain):
                return domain
        
        return None
    
    def getTargetType(self, target: str) -> str:
        if self.isValidIp(target):
            return "ip"
        elif self.isValidDomain(target):
            return "domain"
        return "unknown"
    
    def createInlineKeyboard(self, target: str, target_type: str) -> InlineKeyboardMarkup:
        keyboard = []
        methods = self.checkHostConfigAccess("check-host", "methods")
        
        if target_type == "ip":
            available_methods = ["ip-lookup", "whois", "ping", "tcp", "udp", "dns"]
        else:
            available_methods = ["whois", "ping", "http", "tcp", "udp", "dns"]
        
        row = []
        for method in available_methods:
            if method in methods:
                row.append(InlineKeyboardButton(
                    methods[method], 
                    callback_data=f"{method}:{target}"
                ))
                if len(row) == 2:
                    keyboard.append(row)
                    row = []
        
        if row:
            keyboard.append(row)
        
        return InlineKeyboardMarkup(keyboard)
    
    def executeMethod(self, method: str, target: str) -> str:
        class Args:
            def __init__(self, target: str):
                self.target = target
                self.method = method
                self.max_nodes = 3
        
        args = Args(target)
        
        try:
            method_dict = {
                "ip-lookup": self.ipLookupClass.ip_lookup_run,
                "whois": self.whoisClass.whois_run,
                "ping": self.pingClass.ping_run,
                "http": self.httpClass.http_run,
                "tcp": self.tcpClass.tcp_run,
                "udp": self.udpClass.udp_run,
                "dns": self.dnsClass.dns_run
            }
            
            if method in method_dict:
                result = method_dict[method](args)
                return str(result) if result else f"✅ {method.upper()} check completed for {target}"
            else:
                return f"❌ Method {method} not found"
                
        except Exception as e:
            return f"❌ Error executing {method}: {str(e)}"
    
    def setupHandlers(self):
        @self.bot.message_handler(commands=['start', 'help'])
        def sendWelcome(message):
            welcome_text = """
🔍 **Website & IP Checker Bot**

📤 **Cách sử dụng:**
- Gửi domain: `example.com`
- Gửi URL: `https://google.com`
- Gửi IP: `8.8.8.8`

🛠 **Các method có sẵn:**
🔍 IP Lookup - 📋 WHOIS - 📡 Ping
🌐 HTTP Check - 🔌 TCP - 📤 UDP - 🌍 DNS

📝 Chỉ cần gửi link hoặc domain, bot sẽ tự động tạo menu kiểm tra!
            """
            self.bot.reply_to(message, welcome_text, parse_mode='Markdown')
        
        @self.bot.message_handler(func=lambda message: True)
        def handleMessage(message):
            target = self.extractTarget(message.text)
            
            if not target:
                self.bot.reply_to(
                    message, 
                    "❌ Không thể nhận diện target. Vui lòng gửi domain, URL hoặc IP hợp lệ."
                )
                return
            
            target_type = self.getTargetType(target)
            keyboard = self.createInlineKeyboard(target, target_type)
            
            target_info = f"🎯 **Target:** `{target}`\n📋 **Type:** {target_type.upper()}\n\n🔽 Chọn method để kiểm tra:"
            
            self.bot.reply_to(
                message, 
                target_info, 
                reply_markup=keyboard,
                parse_mode='Markdown'
            )
        
        @self.bot.callback_query_handler(func=lambda call: True)
        def handleCallback(call):
            try:
                method, target = call.data.split(':', 1)
                
                self.bot.answer_callback_query(
                    call.id, 
                    f"🔄 Đang thực hiện {method} cho {target}..."
                )
                
                def runCheck():
                    result = self.executeMethod(method, target)
                    result_text = f"🎯 **Target:** `{target}`\n🛠 **Method:** {method.upper()}\n\n📊 **Kết quả:**\n```\n{result}\n```"
                    
                    self.bot.send_message(
                        call.message.chat.id,
                        result_text,
                        parse_mode='Markdown'
                    )
                
                thread = threading.Thread(target=runCheck)
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                self.bot.answer_callback_query(
                    call.id, 
                    f"❌ Lỗi: {str(e)}"
                )
    
    def run(self):
        print("🤖 Bot started...")
        self.bot.infinity_polling()

if __name__ == "__main__":
    BOT_TOKEN = "7903023411:AAHxE6o_hdibPehD27m1qd9xWnTGYyY_Znc"
    
    checkHostBot = CheckHost(BOT_TOKEN)
    checkHostBot.run()
