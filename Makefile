all:

docker-up:
	sudo docker compose up

docker-rebuild:
	sudo docker compose up --build
