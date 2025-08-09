all:

docker-up:
	sudo docker compose up --remove-orphans

docker-down:
	sudo docker compose down

docker-rebuild:
	sudo docker compose up --build --remove-orphans
