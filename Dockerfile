FROM --platform=linux/amd64 python:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/app/sec

COPY . ./

RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes
RUN apk update && apk add --no-cache docker-cli

RUN curl --compressed https://static.snyk.io/cli/latest/snyk-linux -o snyk 
RUN mv ./snyk /usr/local/bin
RUN chmod +x /usr/local/bin/snyk
CMD ["python", "main.py"]