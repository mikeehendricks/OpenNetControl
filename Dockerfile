FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin onc \
 && mkdir /data && chown onc:onc /data && chmod 700 /data
WORKDIR /app
# Exact, hash-verified dependency versions (see requirements.lock)
COPY requirements.lock .
RUN pip install --require-hashes -r requirements.lock
COPY opennetcontrol ./opennetcontrol
USER 10001
ENV ONC_HOST=0.0.0.0 ONC_PORT=8080 ONC_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('ONC_PORT','8080'), timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "opennetcontrol"]
