# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git libpcap-dev gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /portex ./cmd/portex/

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache libpcap ca-certificates

# Install ONNX runtime for RL model inference (placeholder — real model added in production)
# RUN wget -qO /tmp/onnxruntime.tgz \
#     https://github.com/microsoft/onnxruntime/releases/download/v1.17.1/onnxruntime-linux-x64-1.17.1.tgz \
#     && tar -C /usr/local/lib -xzf /tmp/onnxruntime.tgz --strip-components=2 '*/lib/*.so*' \
#     && rm /tmp/onnxruntime.tgz \
#     && ldconfig /usr/local/lib

COPY --from=builder /portex /usr/local/bin/portex

# Default: show help
ENTRYPOINT ["/usr/local/bin/portex"]
CMD ["--help"]

# Portex requires NET_RAW + NET_ADMIN capabilities for raw socket scanning.
# Run with:
#   docker run --cap-add NET_RAW --cap-add NET_ADMIN --network host portex scan -t <target>
