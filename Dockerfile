# syntax=docker/dockerfile:1.8
FROM golang:1.26.9-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM aquasec/trivy:0.75.0 AS trivy
FROM openpolicyagent/opa:1.21.1-static AS opa

FROM alpine:3.24
RUN apk add --no-cache ca-certificates wget && addgroup -S app && adduser -S -G app app && mkdir -p /data/trivy-cache && chown -R app:app /data
COPY --from=build /out/ /usr/local/bin/
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=opa /opa /usr/local/bin/opa
COPY policies/ /app/policies/
WORKDIR /app
USER app
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/api"]
