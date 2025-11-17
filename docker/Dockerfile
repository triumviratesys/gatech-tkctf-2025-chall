FROM ubuntu:18.04

RUN adduser --disabled-password --gecos '' ctf

RUN apt update && apt install -y socat

COPY flag /flag
COPY target /target

RUN chmod 444 /flag
RUN chmod 755 /target

USER ctf

CMD ["socat", "-T60", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:timeout 60 /target"]
