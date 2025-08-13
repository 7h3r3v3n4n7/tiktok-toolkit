import json
from urllib.parse import urlparse, parse_qs, unquote
from PySide6.QtCore import QThread, Signal
from logger import logger

class TikTokAuthServer(QThread):
    """Thread to handle OAuth callback server"""
    callback_received = Signal(dict)

    def __init__(self, port=8080):
        super().__init__()
        self.port = port
        self.server = None
        self._callback_handled = False  # Only handle one successful callback

    def run(self):
        logger.debug("AUTH_SERVER", f"Starting OAuth callback server on port {self.port}")
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler

            class CallbackHandler(BaseHTTPRequestHandler):
                def do_GET(inner_self):
                    try:
                        parsed_url = urlparse(inner_self.path)

                        if parsed_url.path != "/callback/":
                            inner_self.send_response(204)
                            inner_self.end_headers()
                            return

                        decoded_query = unquote(parsed_url.query)
                        query_params = parse_qs(decoded_query)

                        # Only process the first valid callback
                        if self._callback_handled:
                            inner_self.send_response(204)
                            inner_self.end_headers()
                            return

                        if 'code' not in query_params:
                            inner_self.send_response(204)
                            inner_self.end_headers()
                            return

                        callback_data = {
                            'code': query_params['code'][0]
                        }

                        if 'state' in query_params:
                            callback_data['state'] = query_params['state'][0]
                        if 'scopes' in query_params:
                            callback_data['scopes'] = query_params['scopes'][0]
                        if 'error' in query_params:
                            callback_data['error'] = query_params['error'][0]
                        if 'error_description' in query_params:
                            callback_data['error_description'] = query_params['error_description'][0]
                        
                        inner_self.send_response(200)
                        inner_self.send_header('Content-type', 'text/html')
                        inner_self.end_headers()

                        html_response = """
                        <html>
                        <head><title>TikTok Login Success</title></head>
                        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                            <h1 style="color: #fe2c55;">TikTok Login Successful!</h1>
                            <p>You can close this window now.</p>
                            <p style="color: #666;">The application will handle the authentication automatically.</p>
                        </body>
                        </html>
                        """
                        inner_self.wfile.write(html_response.encode())

                        self._callback_handled = True
                        logger.debug("AUTH_SERVER", f"Received OAuth callback with code: {callback_data.get('code', '')[:10]}...")
                        self.server.callback_received.emit(callback_data)

                    except Exception as e:
                        logger.error("AUTH_SERVER", "Error handling callback request", e)
                        inner_self.send_response(500)
                        inner_self.end_headers()
                        inner_self.wfile.write(b"<h1>Internal Server Error</h1>")

                def log_message(inner_self, format, *args):
                    pass  # Silence logs

            from http.server import HTTPServer
            self.server = HTTPServer(('localhost', self.port), CallbackHandler)
            self.server.callback_received = self.callback_received
            self.server.serve_forever()

        except Exception as e:
            logger.error("AUTH_SERVER", "Error starting server", e)

    def stop(self):
        if self.server:
            logger.debug("AUTH_SERVER", "Shutting down OAuth callback server")
            self.server.shutdown() 