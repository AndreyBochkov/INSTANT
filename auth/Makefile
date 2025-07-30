SOURCES = ./cmd/* ./internal/config/* ./internal/transport/* ./pkg/logger/* ./pkg/postgres/* ./go.* ./pkg/aes/*

all:

build: $(SOURCES)
	go build -o ./build/auth ./cmd/auth.go

run:
	./build/auth

pg-up:
	sudo docker compose -f ./../pg-compose.yml up