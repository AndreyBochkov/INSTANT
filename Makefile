all:

docker-up:
	sudo docker compose up

docker-down:
	sudo docker compose down

docker-rebuild:
	sudo docker compose up --build
