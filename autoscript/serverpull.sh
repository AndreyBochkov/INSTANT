#!/bin/bash

cd ./../ # docker-compose.yml folder
sudo /path/to/docker exec INSTANT_db pg_dumpall -U postgres > "./../dump_$(date +"%Y-%m-%d_%H-%M-%S").sql" # visudo recommended