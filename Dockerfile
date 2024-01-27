FROM --platform=linux/amd64 python:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/app/sec

COPY . ./

RUN apt-get update && \
    curl -fsSL https://get.docker.com -o install-docker.sh
    
RUN sh install-docker.sh --version 24

RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes

COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk

CMD  ["sh", "-c","mkdir $HOME/.docker && cp -r /tmp/.docker/..data/config.json $HOME/.docker && service docker restart && python main.py"]
