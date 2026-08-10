# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-gateway ./cmd/api

# Runtime stage
FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/auth-gateway .

EXPOSE 8080

CMD ["./auth-gateway"]