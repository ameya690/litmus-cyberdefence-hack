FROM python:3.12-slim
WORKDIR /app
COPY exploit.py /app/exploit.py
# Network-only attacker: no target source, no challenge volume, stdlib only.
# It idles; the harness execs exploit.py to drive requests at the target.
CMD ["sleep", "infinity"]
