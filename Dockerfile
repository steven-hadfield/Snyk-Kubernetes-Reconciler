FROM --platform=linux/amd64 python:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/app/sec

COPY . ./


RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
RUN chmod a+r /etc/apt/keyrings/docker.gpg
RUN apt-get update
RUN apt-get -y install apt-transport-https ca-certificates gnupg software-properties-common

RUN echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update
RUN apt-get install -y docker-ce-cli docker-ce

RUN usermod -aG docker root
RUN service docker restart
RUN service docker start

RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes


COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk

CMD ["python", "main.py"]