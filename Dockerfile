FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir paramiko==3.5.1
COPY app.py cli_runtime.py officeconnect.py dashboard.html login.html settings.html test_app.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python","app.py"]
