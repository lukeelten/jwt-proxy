FROM registry.access.redhat.com/ubi9-minimal
LABEL maintainer="Tobias Derksen <t.derksen@mailbox.org>"

ENV TZ=Europe/Berlin

COPY jwt-proxy /jwt-proxy

ENTRYPOINT [ "/jwt-proxy" ]
CMD []
