# syntax=docker/dockerfile:1

FROM node:24-alpine AS web-build
WORKDIR /source/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.6-alpine AS go-build
WORKDIR /source
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /source/internal/webui/dist/ internal/webui/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/haven-hub ./cmd/haven-hub
RUN mkdir -p /out/data && touch /out/data/.haven-volume

FROM scratch
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-build /out/haven-hub /haven-hub
COPY --from=go-build --chown=65532:65532 /out/data/ /var/lib/haven/
USER 65532:65532
VOLUME ["/var/lib/haven"]
EXPOSE 8080
ENV HAVEN_LISTEN_ADDRESS=0.0.0.0:8080 \
    HAVEN_DATA_PATH=/var/lib/haven/haven.db \
    HAVEN_STATE_DIRECTORY=/var/lib/haven \
    HAVEN_RETENTION_DAYS=90 \
    HAVEN_HEALTHCHECK_URL=http://127.0.0.1:8080/api/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/haven-hub", "healthcheck"]
ENTRYPOINT ["/haven-hub"]
