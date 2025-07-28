FROM golang:1.23.6-alpine3.21 AS builder
WORKDIR /app
COPY go.mod go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ./build/auth ./cmd/auth.go

FROM alpine:3.21
WORKDIR /app

COPY --from=builder /app/build/auth ./build/
COPY --from=builder /app/config/config.env ./config/
COPY --from=builder /app/db/migrations/* ./db/migrations/

EXPOSE 51756

CMD ["./build/auth"]