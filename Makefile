all:

docker-up:
	sudo docker compose up --remove-orphans

docker-down:
	sudo docker compose down -v

docker-rebuild:
	sudo docker compose up --build --remove-orphans
