SOURCES = ./cmd/* ./internal/*/* ./pkg/*/*
all:

build: $(SOURCES)
	go build -o ./build/instant ./cmd/instant.go

run:
	./build/instant
