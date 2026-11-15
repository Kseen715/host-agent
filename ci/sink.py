"""Takes every POST and answers 204: Prometheus and Loki for benches."""

import http.server
import sys


class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


address = ("127.0.0.1", int(sys.argv[1]))
http.server.ThreadingHTTPServer(address, Sink).serve_forever()
