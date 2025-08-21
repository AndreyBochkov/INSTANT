package postgres

import (
	"fmt"
	"context"
	"errors"
	"time"
	"instant_service/internal/config"
	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5"
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

func (p PGXPool) InsertUser(iKey []byte, login string) (int, error) {
	id := 0
	err := p.pgxPool.QueryRow(context.Background(), "INSERT INTO auth_schema.users (ikey, login) VALUES ($1, $2) RETURNING id;", iKey, login).Scan(&id)
	return id, err
}

func (p PGXPool) GetIDAndIKeyByLogin(login string) (int, []byte, error) {
	id := -1
	iKey := []byte{}
	err := p.pgxPool.QueryRow(context.Background(), "SELECT id, ikey FROM auth_schema.users WHERE login=$1;", login).Scan(&id, &iKey)
	return id, iKey, err
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
	rows, err := p.pgxPool.Query(context.Background(), "SELECT id, login FROM auth_schema.users WHERE login ILIKE $1", query+"%")
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

func (p PGXPool) GetMessageListByUserIDAndChatIDAndParam(userID, chatID, offset int) ([]Message, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT messageid, ts, body, sender=$1 AS mine FROM chat_schema.messages WHERE chatid=$2 ORDER BY ts DECS LIMIT $3 OFFSET $4;", userID, chatID, 20, offset*20)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Message])
}

func (p PGXPool) GetSyncMessageListByReceiverIDAndAfter(userID int, after int64) ([]SyncMessage, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT messageid, ts, body, chatid FROM chat_schema.messages WHERE receiver=%1 AND ts>$2 ORDER BY ts DECS;", userID, after)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SyncMessage])
}

func (p PGXPool) InsertMessage(senderID, receiverID, chatID int, body string) (int64, int64, error) {
	messageID := int64(0)
	ts := int64(0)
	err := p.pgxPool.QueryRow(context.Background(), "INSERT INTO chat_schema.messages (chatid, body, sender, receiver) VALUES ($1, $2, $3, $4) RETURNING messageid, ts;", chatID, body, senderID, receiverID).Scan(&messageID, &ts)
	return messageID, ts, err
}

func (p PGXPool) UpdateIKeyByID(userid int, iKey []byte) error {
	_, err := p.pgxPool.Exec(context.Background(), "UPDATE auth_schema.users SET ikey=$2 WHERE id=$1;", userid, iKey)
	return err
}

func (p PGXPool) GetIDByIKeyUpdatingTS(iKey []byte) int {
	id := -1
	p.pgxPool.QueryRow(context.Background(), "UPDATE auth_schema.users SET ts=$1 WHERE ikey=$2 RETURNING id", time.Now().Unix(), iKey).Scan(&id)
	return id
}

// =====

func (p PGXPool) GetLoginByUserID(id int) (string, error) {
	login := ""
	err := p.pgxPool.QueryRow(context.Background(), "SELECT login FROM auth_schema.users WHERE id=$1;", id).Scan(&login)
	return login, err
}

func (p PGXPool) Close() {
	p.pgxPool.Close()
}