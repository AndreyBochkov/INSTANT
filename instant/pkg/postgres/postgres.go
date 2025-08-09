package postgres

import (
	"fmt"
	"context"
	"errors"
	"instant_service/internal/config"
	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PGXPool struct {
	pgxPool *pgxpool.Pool
}

func New(ctx context.Context, cfg config.PGConfig, path string) (PGXPool, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&pool_max_conns=%d&pool_min_conns=%d",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,

		cfg.MaxConns,
		cfg.MinConns,
	)

	pgxPool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return PGXPool{nil}, fmt.Errorf("Unable to connect to database: %w", err)
	}

	m, err := migrate.New(
		"file://"+path,
		fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&x-migrations-table=auth_schema",
			cfg.Username,
			cfg.Password,
			cfg.Host,
			cfg.Port,
			cfg.Database,
		),
	)
	if err != nil {
		return PGXPool{nil}, fmt.Errorf("Unable to create migrations: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return PGXPool{nil}, fmt.Errorf("Unable to run migrations: %w", err)
	}

	return PGXPool{pgxPool}, nil
}

func (p PGXPool) InsertUser(login, password, name string) error {
	_, err := p.pgxPool.Exec(context.Background(), "INSERT INTO auth_schema.users (login, password, name) VALUES ($1, $2, $3);", login, password, name)
	return err
}

func (p PGXPool) GetIDAndNameAndPasswordByLogin(login string) (int, string, string, error) {
	id := -1
	name := ""
	password := ""
	err := p.pgxPool.QueryRow(context.Background(), "SELECT id, name, password FROM auth_schema.users WHERE login=$1;", login).Scan(&id, &name, &password)
	return id, name, password, err
}

// =====

func (p PGXPool) GetChatListByID(id int) ([]Chat, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT chatid, user2, CASE WHEN user1=$1 THEN label1 ELSE label2 END AS label FROM chat_schema.chats WHERE user1=$1 OR user2=$1;", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Chat])
}

func (p PGXPool) SearchUsersByQuery(query string) ([]User, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT id, login, name FROM auth_schema.users WHERE login ILIKE $1", query)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

func (p PGXPool) InsertChat(id1, id2 int, label1, label2 string) (int, error) {
	chatID := 0
	err := p.pgxPool.QueryRow(context.Background(), "INSERT INTO chat_schema.chats (user1, user2, label1, label2) VALUES ($1, $2, $3, $4) RETURNING chatid;", id1, id2, label1, label2).Scan(&chatID)
	return chatID, err
}

func (p PGXPool) GetMessageListByUserIDAndChatIDAndParams(userID, chatID, num, offset int) ([]Message, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT messageid, ts, body, sender=$1 AS mine FROM chat_schema.messages WHERE chatid=$2 ORDER BY ts DECS LIMIT $3 OFFSET $4;", userID, chatID, num, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Message])
}

func (p PGXPool) InsertMessage(senderID, receiverID, chatID int, body string) (int64, int64, error) {
	messageID := int64(0)
	ts := int64(0)
	err := p.pgxPool.QueryRow(context.Background(), "INSERT INTO chat_schema.messages (chatid, body, sender, receiver) VALUES ($1, $2, $3, $4) RETURNING messageid, ts;", chatID, body, senderID, receiverID).Scan(&messageID, &ts)
	return messageID, ts, err
}

// =====

func (p PGXPool) VerifyLoginAndID(login string, id int) bool {
	dbid := 0
	err := p.pgxPool.QueryRow(context.Background(), "SELECT id FROM auth_schema.users WHERE login=$1;", login).Scan(&dbid)
	return err == nil && id == dbid
}

func (p PGXPool) GetNameByUserID(id int) (string, error) {
	name := ""
	err := p.pgxPool.QueryRow(context.Background(), "SELECT name FROM auth_schema.users WHERE id=$1;", id).Scan(&name)
	return name, err
}

func (p PGXPool) Close() {
	p.pgxPool.Close()
}