import uvicorn

from .app import create_app
from .config import Settings

if __name__ == "__main__":
    s = Settings()
    # proxy_headers=False: uvicorn must NOT rewrite the client address from X-Forwarded-For (it did so for any peer on
# 127.0.0.1, which let a local/co-located caller forge its IP and bypass lockout + rate limits). app.client_ip() does
# the trust decision. server_header=False hides the server banner.
    uvicorn.run(create_app(s), host=s.host, port=s.port, log_level="info", proxy_headers=False,
                server_header=False, timeout_keep_alive=10)
