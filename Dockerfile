FROM python:latest

WORKDIR /usr/app/sec

COPY . ./


RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes
CMD ["python", "main.py"]