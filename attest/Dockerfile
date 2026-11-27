# Build with the storm builder: docker buildx build --builder storm --target <attester|verifier> .
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/attester ./cmd/attester && \
    CGO_ENABLED=0 go build -trimpath -o /out/verifier ./cmd/verifier

# Runs as root: Fly's /.fly/api socket, which issues the OIDC token, accepts only root.
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS verifier
COPY --from=build /out/verifier /verifier
EXPOSE 8080
ENTRYPOINT ["/verifier"]

# Runs as root: /dev/tpmrm0 and /var/lib/tailscale are root-owned on Talos.
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS attester
COPY --from=build /out/attester /attester
ENTRYPOINT ["/attester"]
