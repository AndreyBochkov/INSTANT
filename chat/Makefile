SOURCES = ./cmd/* ./internal/config/* ./internal/transport/* ./pkg/logger/* ./pkg/postgres/* ./go.* ./pkg/aes/*

all:

build: $(SOURCES)
	go build -o ./build/chat ./cmd/chat.go

run:
	./build/chat

docker-up:
	sudo docker compose -f ./../docker-compose.yml up

docker-rebuild:
	sudo docker compose -f ./../docker-compose.yml up --build

pg-up:
	sudo docker compose -f ./../pg-compose.yml up