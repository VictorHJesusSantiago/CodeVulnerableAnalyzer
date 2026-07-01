FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system vulnscan && useradd --system --gid vulnscan --home /app vulnscan
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=vulnscan:vulnscan analyzer analyzer
COPY --chown=vulnscan:vulnscan main.py .
USER vulnscan
ENTRYPOINT ["python", "main.py"]
