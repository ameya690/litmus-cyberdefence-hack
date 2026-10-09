FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY docs ./docs
# The challenge secret is bind-mounted at /challenge (OUTSIDE /app/docs), so the
# only way to read it is to escape DOCS_DIR via the path-traversal bug.
ENV DOCS_DIR=/app/docs PORT=5000
EXPOSE 5000
CMD ["python", "app.py"]
