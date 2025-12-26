# Build go
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o server-skeleton -trimpath -ldflags "-s -w" ./cmd/server

# Release
FROM  alpine
# Install dependencies
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/server-skeleton /usr/local/bin
ENTRYPOINT ["server-skeleton"]
