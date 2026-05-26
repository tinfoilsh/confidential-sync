FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS builder

ARG GIT_SHA=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.gitSHA=${GIT_SHA}" \
    -o sync-enclave .

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN apk --no-cache add ca-certificates tini \
    && addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /app/sync-enclave .

USER app

EXPOSE 8089

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["./sync-enclave"]
