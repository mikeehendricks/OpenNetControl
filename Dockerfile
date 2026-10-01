FROM python:3.12-slim
RUN useradd -m -u 10001 onc
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY opennetcontrol ./opennetcontrol
USER onc
ENV ONC_HOST=0.0.0.0 ONC_PORT=8080 ONC_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
CMD ["python", "-m", "opennetcontrol"]
