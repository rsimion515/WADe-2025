# callback_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        challenge = qs.get('hub.challenge', [''])[0]
        mode = qs.get('hub.mode', [''])[0]
        topic = qs.get('hub.topic', [''])[0]
        print(f"Verification request: mode={mode}, topic={topic}, challenge={challenge}")
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()
        self.wfile.write(challenge.encode())
    def do_POST(self):
        # Print the JSON payload received from the hub
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Notification received: {post_data.decode()}")
        self.send_response(200)
        self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8001), Handler)
    print("Callback server listening on http://0.0.0.0:8001/callback")
    server.serve_forever()