FROM ubuntu:16.04
MAINTAINER fweasd
WORKDIR /
RUN apt update 
RUN apt install -y libssl-dev xinetd python2.7 libseccomp-dev
RUN apt autoremove && apt autoclean 
RUN useradd -m shellcode_writer
COPY ./src/home /home/shellcode_writer
COPY ./xinetd /etc/xinetd.d/xinetd

RUN chown -R root:root /home/shellcode_writer && \
    chown -R root:root /etc/xinetd.d/xinetd && \
    find / -type d -perm /0002 -exec chmod o-w {} + 2>/dev/null ; \
    find / -type f -perm /0002 -exec chmod o-w {} + 2>/dev/null ; \
    echo 'Finish'

CMD ["/usr/sbin/xinetd","-dontfork"]
