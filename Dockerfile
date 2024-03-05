FROM registry.access.redhat.com/ubi9-minimal
LABEL maintainer="Tobias Derksen <t.derksen@mailbox.org>"

ENV TZ=Europe/Berlin CONFIG_FILE=config.yaml

COPY jwt-proxy /jwt-proxy

ENTRYPOINT [ "/jwt-proxy" ]
CMD []
