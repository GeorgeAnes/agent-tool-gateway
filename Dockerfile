FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home app
COPY app.py bench.py ./
COPY toolgate toolgate
COPY web web
COPY data data
USER app
ENV HOST=0.0.0.0
CMD ["python", "app.py"]
