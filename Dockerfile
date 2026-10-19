FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir paramiko==3.5.1
COPY app.py availability.py cli_runtime.py officeconnect.py dashboard.html login.html settings.html wizard.html setup_config.py test_app.py test_setup.py test_availability.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python","app.py"]
