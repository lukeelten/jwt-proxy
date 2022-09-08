FROM registry.access.redhat.com/ubi9/go-toolset:1.17.12 as builder

USER root
RUN mkdir -p /app
WORKDIR /app
COPY . .
RUN go build -o jwt-proxy -ldflags="-s -w" ./cmd/jwt-proxy

FROM registry.access.redhat.com/ubi9-minimal

ENV TZ=Europe/Berlin

COPY --from=builder /app/jwt-proxy /jwt-proxy

ENTRYPOINT [ "/jwt-proxy" ]
CMD []