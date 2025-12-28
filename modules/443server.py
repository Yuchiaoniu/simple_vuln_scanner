import http.server
import ssl

# 1. 定義一個自定義的處理器
class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # 在發送所有標頭之前，插入我們自定義的安全標頭
        self.send_header('Server', 'Secure-Gateway')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'")

        # 呼叫父類別的原有方法，完成標頭發送
        super().end_headers()

# 2. 設定伺服器位址與處理器
server_address = ('127.0.0.1', 443)
httpd = http.server.HTTPServer(server_address, SecureHandler)

# 3. 設定 SSL 上下文 (TLS 1.2/1.3 安全設定)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# 4. 將 Socket 加密
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("🛡️ 安全 TLS 伺服器已在 443 Port 啟動...")
print("檢查項：TLS 加密、Server 隱藏、X-Frame-Options、NOSNIFF、CSP")
httpd.serve_forever()