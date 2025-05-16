# BUILDER
FROM golang:1.22-alpine AS builder
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app
COPY . .

RUN go build -o api-gateway cmd/api-gateway/main.go

# RUNNER
FROM alpine:latest
COPY --from=builder /app/api-gateway /api-gateway

ENV ENV=prod

EXPOSE 3000
ENTRYPOINT ["./api-gateway"]
