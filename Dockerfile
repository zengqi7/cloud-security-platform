# syntax=docker/dockerfile:1.8
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cloudguard ./cmd/cloudguard && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/key ./cmd/key && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e AS opa
FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates wget && addgroup -S -g 10001 app && adduser -S -u 10001 -G app app && mkdir -p /data/trivy-cache && chown -R app:app /data
COPY --from=build /out/ /usr/local/bin/
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=opa /opa /usr/local/bin/opa
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY policies/ /app/policies/
WORKDIR /app
USER 10001:10001
EXPOSE 8082 8083
ENTRYPOINT ["/usr/local/bin/api"]
