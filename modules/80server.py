from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def home():
    resp = make_response("<h1>這是一個具備安全標頭的伺服器</h1>")
    
    # 手動加入安全標頭
    resp.headers['Server'] = 'Secure-Gateway' # 隱藏真實版本
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN' # 防止點擊劫持
    resp.headers['X-Content-Type-Options'] = 'nosniff' # 防止類型欺騙
    resp.headers['Content-Security-Policy'] = "default-src 'self'" # 嚴格資源載入
    
    return resp

if __name__ == '__main__':
    # 注意：443 port 在某些系統需管理員權限
    app.run(host='127.0.0.1', port=80, debug=True)