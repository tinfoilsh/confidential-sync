FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o sync-enclave .

FROM alpine:latest

RUN apk --no-cache add ca-certificates tini \
    && addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /app/sync-enclave .

USER app

EXPOSE 8089

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["./sync-enclave"]
