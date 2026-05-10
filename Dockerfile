FROM python:3.11-slim
WORKDIR /app
COPY python/requirements.txt /app/python/requirements.txt
RUN pip install --no-cache-dir -r python/requirements.txt
COPY . /app
RUN mkdir -p /app/data /app/logs /app/uploads
ENV PYTHONUNBUFFERED=1 \
    PORT=7860 \
    SQLITE_PATH=/app/data/phishing.sqlite \
    ALLOWED_ORIGINS=*
EXPOSE 7860
WORKDIR /app/python
CMD ["gunicorn", "-b", "0.0.0.0:7860", "-w", "2", "--timeout", "120", "simple_app:app"]
