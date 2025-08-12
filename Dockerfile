FROM python:3.12-slim
RUN apt-get update && apt-get install -y nmap exploitdb && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["empusa"]