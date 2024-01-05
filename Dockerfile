FROM --platform=linux/amd64 python:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/app/sec

COPY . ./

RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes


<<<<<<< HEAD
=======

>>>>>>> c90e31867b93a37c8046d27b11d2000e6cfa0ff7
COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk

CMD ["python", "main.py"]