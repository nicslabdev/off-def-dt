FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY services/emulator/emulator.py /app/emulator.py
CMD ["python", "emulator.py"]
