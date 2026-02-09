FROM debian@sha256:56ff6d36d4eb3db13a741b342ec466f121480b5edded42e4b7ee850ce7a418ee
WORKDIR /app
COPY pwn_the_time_war /app/run
COPY flag.txt /app/flag.txt
RUN chmod 755 /app/run
RUN apt update
RUN apt install gdb git -y
WORKDIR /opt/
RUN git clone http://github.com/pwndbg/pwndbg
WORKDIR /opt/pwndbg
RUN ./setup.sh

RUN apt install socat procps -y
RUN chmod +x /app/run

CMD ["socat", "tcp-l:5000,reuseaddr,fork", "EXEC:/app/run"]
