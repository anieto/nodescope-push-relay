FROM golang:1.26.0-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/nodescope-push-relay .
RUN mkdir -p /out/data

FROM scratch
COPY --from=build /out/nodescope-push-relay /nodescope-push-relay
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/data /data
ENV RELAY_ADDR=0.0.0.0:8080 RELAY_STATE_PATH=/data/relay-state.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/nodescope-push-relay"]
