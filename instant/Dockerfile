FROM golang:1.24.4-alpine3.21 AS builder
WORKDIR /app
COPY go.mod go.sum .
RUN go mod download

COPY ./cmd/* ./cmd/
COPY ./internal/config/* ./internal/config/
COPY ./internal/transport/* ./internal/transport/
COPY ./pkg/aes/* ./pkg/aes/
COPY ./pkg/logger/* ./pkg/logger/
COPY ./pkg/postgres/* ./pkg/postgres/
RUN CGO_ENABLED=0 GOOS=linux go build -o ./build/instant ./cmd/instant.go

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /app/build/instant ./build/
COPY ./config/* ./config/
COPY ./db/migrations/* ./db/migrations/

EXPOSE 51756

CMD ["./build/instant"]