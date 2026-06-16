FROM registry.access.redhat.com/ubi9-minimal
LABEL maintainer="Tobias Derksen <t.derksen@mailbox.org>"

ENV TZ=Europe/Berlin

COPY jwt-proxy /jwt-proxy

# Run as a non-root user (uid 65532 mirrors the common "nonroot" convention)
USER 65532:65532

ENTRYPOINT [ "/jwt-proxy" ]
CMD []
