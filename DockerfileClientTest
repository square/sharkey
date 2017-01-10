# Dockerfile for integration testing
#
# Not intended to be used for an actual setup
FROM golang
MAINTAINER Christopher Denny <chris.denny@utexas.edu>
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:password' | chpasswd
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# Setup key based ssh
RUN mkdir /root/.ssh && chmod 700 /root/.ssh
ADD test/integration/id_rsa.pub /root/.ssh/authorized_keys
ADD test/integration/id_rsa.pub /root/.ssh/id_rsa.pub
ADD test/integration/id_rsa /root/.ssh/id_rsa
RUN chmod 400 /root/.ssh/authorized_keys && chown root:root /root/.ssh/* && chmod 600 /root/.ssh/*

COPY . /go/src/github.com/square/sharkey

RUN cd /go/src/github.com/square/sharkey && \
	go build -v -o /usr/bin/sharkey-client ./client && \
    cp test/integration/client_entry.sh /usr/bin/entrypoint.sh && \
    chmod +x /usr/bin/entrypoint.sh

RUN echo "HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub" >> /etc/ssh/sshd_config
RUN echo "HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub" >> /etc/ssh/sshd_config
RUN echo "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub" >> /etc/ssh/sshd_config

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
