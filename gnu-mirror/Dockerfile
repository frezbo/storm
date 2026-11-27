# syntax=docker/dockerfile:1

ARG BUILD_IMAGE=golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647

FROM ${BUILD_IMAGE} AS build
WORKDIR /src

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /gnu-mirror .

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /gnu-mirror /gnu-mirror

USER 65532:65532
EXPOSE 15008
ENTRYPOINT ["/gnu-mirror"]
