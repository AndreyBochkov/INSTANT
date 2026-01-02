## Измените файл sudoers, чтобы мочь запускать скрипты автоматически. / Change the sudoers file to be able to run scripts automaticlly.

```

... Добавьте в конце: / Add in the end:

user ALL=(ALL) NOPASSWD: /path/to/docker compose up --build -d
user ALL=(ALL) NOPASSWD: /path/to/docker exec INSTANT_db pg_dumpall -U postgres
user ALL=(ALL) NOPASSWD: /path/to/docker compose down
```

Отредактируйте скрипты и строки sudoers, заменив `/path/to/docker` на результат команды `which docker`. / Change `/path/to/docker`to output of`which docker` command in the scripts and in the sudoers lines.
