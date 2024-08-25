FROM python:3.9-slim

WORKDIR /app

# Remove this line as we'll mount the file instead
# COPY ./ip_blacklist.txt /app/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY suricata_analyzer.py .

CMD ["python", "suricata_analyzer.py"]
