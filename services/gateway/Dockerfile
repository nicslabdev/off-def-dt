FROM python:3.11-slim
WORKDIR /app
# Expect the build context to include the repository root so requirements.txt is available
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY services/gateway/gateway.py /app/gateway.py
CMD ["python", "gateway.py"]
