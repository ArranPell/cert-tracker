FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=America/St_Johns
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/certtracker certtracker && mkdir /data && chown certtracker /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY certtracker ./certtracker
USER certtracker
VOLUME /data
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "120", "certtracker.wsgi:app"]
