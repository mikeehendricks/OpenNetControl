import uvicorn

from .app import create_app
from .config import Settings

if __name__ == "__main__":
    s = Settings()
    uvicorn.run(create_app(s), host=s.host, port=s.port, log_level="info")
