"""Run a local HTTP server for the demo webapp."""

import argparse
import errno
from functools import partial
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
import socketserver


class _ReusableTCPServer(socketserver.TCPServer):
    """TCP server with address reuse for quick restarts."""

    allow_reuse_address = True


class _DemoRequestHandler(SimpleHTTPRequestHandler):
    """Request handler that ignores client disconnects."""

    def copyfile(self, source, outputfile) -> None:
        try:
            super().copyfile(source, outputfile)
        except (BrokenPipeError, ConnectionResetError):
            return
        except OSError as exc:
            if exc.errno == errno.EPIPE:
                return
            raise


def main() -> None:
    """Start the local demo server."""

    parser = argparse.ArgumentParser(description="Run the BridgeWarden demo webapp.")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on.")
    args = parser.parse_args()

    web_root = Path(__file__).resolve().parent / "webapp"
    handler = partial(_DemoRequestHandler, directory=str(web_root))
    with _ReusableTCPServer(("127.0.0.1", args.port), handler) as httpd:
        print(f"Serving demo webapp at http://127.0.0.1:{args.port}/")
        print("Press Ctrl+C to stop.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
