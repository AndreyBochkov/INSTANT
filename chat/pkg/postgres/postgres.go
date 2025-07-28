package postgres

import (
	"fmt"
	"context"
	"errors"
	"time"
	
	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5"

	"chat_service/internal/config"
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
		fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&x-migrations-table=chat_schema",
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

func (p PGXPool) InsertChat(id1, id2 int) (int, error) {
	chatID := 0
	_, err := p.pgxPool.Exec(context.Background(), "INSERT INTO chat_schema.users (user1, user2) VALUES ($1, $2) RETURNING chatid;", id1, id2).Scan(&chatID)
	return chatID, err
}

func (p PGXPool) GetMessageListByUserIDAndChatIDAndParams(userID, chatID, num, offset int) ([]Message, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT messageid, ts, body, sender=$1 AS mine FROM chat_schema.messages WHERE chatid=$2 ORDER BY ts DECS LIMIT $3 OFFSET $4;", userID, chatID, num, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Message])
}

func (p PGXPool) InsertMessage(userID, chatID int, body string) (int64, time.Time) {
	messageID := int64(0)
	ts := time.Time{}
	_, err := p.pgxPool.Exec(context.Background(), "INSERT INTO chat_schema.messages (chatid, body, sender) VALUES ($1, $2, $3) RETURNING messageid, ts;", id1, id2).Scan(&messageID, &ts)
	return messageID, ts, err
}

// =====

func (p PGXPool) VerifyLoginAndID(login string, id int) bool {
	dbid := 0
	_, err := p.pgxPool.QueryRow(context,Background(), "SELECT id FROM auth_schema.users WHERE login=$1 AND id=$2;", login, id).Scan(&dbid)
	return err == nil && id == dbid
}

func (p PGXPool) Close() {
	p.pgxPool.Close()
}