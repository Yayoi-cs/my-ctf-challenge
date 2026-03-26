FROM ubuntu:24.04@sha256:4fdf0125919d24aec972544669dcd7d6a26a8ad7e6561c73d5549bd6db258ac2
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && \
    apt-get -y install xinetd && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r pwn && \
    useradd -r -g pwn -d /home/pwn pwn

RUN cat > /etc/xinetd.d/pwn << 'EOF' && chmod 444 /etc/xinetd.d/pwn
service pwn
{
  type           = UNLISTED
  disable        = no
  socket_type    = stream
  protocol       = tcp
  wait           = no
  user           = pwn
  bind           = 0.0.0.0
  port           = 9999
  server         = /usr/bin/timeout
  server_args    = 180 /home/pwn/chal
}
EOF

WORKDIR /home/pwn
COPY --chmod=550 chal .
COPY --chmod=444 flag.txt /flag.txt
RUN chown -R root:pwn /home/pwn

EXPOSE 9999
CMD ["xinetd", "-dontfork"]

