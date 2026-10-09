FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.1.3
COPY proxy.py /app/proxy.py
ENV TARGET_URL=http://target:5000 CAPTURE_FILE=/capture/wire.log PORT=8080
EXPOSE 8080
CMD ["python", "proxy.py"]
