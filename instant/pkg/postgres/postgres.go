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

// =====

func (p PGXPool) GetChatListByID(userid int) ([]Chat, error) {
	rows, err := p.pgxPool.Query(context.Background(), "WITH t AS (SELECT chatid, role FROM chat_schema.ties WHERE userid=$1) SELECT t.chatid, g.label, (t.role='admin') AS cansend FROM t JOIN chat_schema.groups g ON g.chatid=t.chatid AND g.deleted=FALSE;", userid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Chat])
}

func (p PGXPool) SearchUsersByQuery(query string) ([]User, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT id, login FROM auth_schema.users WHERE login ILIKE $1 ORDER BY ts DESC LIMIT 20;", query)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

func (p PGXPool) GetIsAdminByUserIDAndChatID(userid int, chatid int) (bool, error) {
	chatDeleted := false
	err := p.pgxPool.QueryRow(context.Background(), "SELECT deleted FROM chat_schema.groups WHERE chatid=$1;", chatid).Scan(&chatDeleted)
	if err == nil && chatDeleted {
		return false, pgx.ErrNoRows
	}

	isAdmin := false
	if err == nil {
		err = p.pgxPool.QueryRow(context.Background(), "SELECT role='admin'::chatrole AS isadmin FROM chat_schema.ties WHERE userid=$1 AND chatid=$2;", userid, chatid).Scan(&isAdmin)
	}
	return isAdmin, err
}

func (p PGXPool) GetListenersByChatID(chatid int) ([]User, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT t.userid, u.login FROM chat_schema.ties t JOIN auth_schema.users u ON t.userid=u.id WHERE t.chatid=$1 AND role='listener';", chatid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

func (p PGXPool) GetAdminsByChatID(chatid int) ([]User, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT t.userid, u.login FROM chat_schema.ties t JOIN auth_schema.users u ON t.userid=u.id WHERE t.chatid=$1 AND role='admin';", chatid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

func (p PGXPool) InsertChat(admins []int, listeners []int, label string) (int, error) {
	chatID := 0
	err := p.pgxPool.QueryRow(context.Background(), "WITH g AS (INSERT INTO chat_schema.groups (label) VALUES ($3) RETURNING chatid), u AS (INSERT INTO chat_schema.ties (chatid, userid, role) SELECT g.chatid, unnest($1::int[]), 'admin'::chatrole FROM g UNION ALL SELECT g.chatid, unnest($2::int[]), 'listener'::chatrole FROM g RETURNING chatid) SELECT chatid FROM g;", admins, listeners, label).Scan(&chatID)
	return chatID, err
}

func (p PGXPool) GetMessageListByChatIDAndParam(chatID, offset int) ([]Message, error) {
	rows, err := p.pgxPool.Query(context.Background(), "SELECT messageid, ts, body, sender FROM chat_schema.broadcasts WHERE chatid=$1 ORDER BY ts DESC LIMIT 21 OFFSET $2;", chatID, offset*21)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Message])
}

func (p PGXPool) InsertMessage(senderID, chatID int, body string) (int64, int64, error) {
	messageID := int64(0)
	ts := int64(0)
	err := p.pgxPool.QueryRow(context.Background(), "INSERT INTO chat_schema.broadcasts (chatid, body, sender) VALUES ($1, $2, $3) RETURNING messageid, ts;", chatID, body, senderID).Scan(&messageID, &ts)
	return messageID, ts, err
}

func (p PGXPool) GetUsersByChatID(chatID int) []int {
	users := []int{}
	p.pgxPool.QueryRow(context.Background(), "SELECT ARRAY(SELECT t.userid FROM chat_schema.ties t WHERE t.chatid=$1);", chatID).Scan(&users)
	return users
}

func (p PGXPool) GetAdminsIDsByChatID(chatID int) []int {
	users := []int{}
	p.pgxPool.QueryRow(context.Background(), "SELECT ARRAY(SELECT t.userid FROM chat_schema.ties t WHERE t.chatid=$1 AND t.role='admin'::chatrole);", chatID).Scan(&users)
	return users
}

func (p PGXPool) GetListenersIDsByChatID(chatID int) []int {
	users := []int{}
	p.pgxPool.QueryRow(context.Background(), "SELECT ARRAY(SELECT t.userid FROM chat_schema.ties t WHERE t.chatid=$1 AND t.role='listener'::chatrole);", chatID).Scan(&users)
	return users
}

func (p PGXPool) GetLabelByChatID(chatID int) string {
	label := ""
	p.pgxPool.QueryRow(context.Background(), "SELECT label FROM chat_schema.groups WHERE chatid=$1 AND deleted=FALSE;", chatID).Scan(&label)
	return label
}

func (p PGXPool) UpdateIKeyByID(userid int, iKey []byte) error {
	_, err := p.pgxPool.Exec(context.Background(), "UPDATE auth_schema.users SET ikey=$2 WHERE id=$1;", userid, iKey)
	return err
}

func (p PGXPool) GetIDByIKeyUpdatingTS(iKey []byte) int {
	id := -1
	p.pgxPool.QueryRow(context.Background(), "UPDATE auth_schema.users SET ts=(EXTRACT(EPOCH FROM NOW())) WHERE ikey=$1 RETURNING id;", iKey).Scan(&id)
	return id
}

// =====

func (p PGXPool) InsertAlert(userid int, body string) error {
	_, err := p.pgxPool.Exec(context.Background(), "INSERT INTO auth_schema.alerts (userid, body) VALUES ($1, $2);", userid, body)
	return err
}

func (p PGXPool) GetAlertsByID(userid int) ([]Alert, error) {
	rows, err := p.pgxPool.Query(context.Background(), "UPDATE auth_schema.alerts SET opened=TRUE WHERE userid=$1 RETURNING alertid, ts, body;", userid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Alert])
}

// =====

func (p PGXPool) GetLoginByID(userid int) string {
	login := "???"
	p.pgxPool.QueryRow(context.Background(), "SELECT login FROM auth_schema.users WHERE id=$1;", userid).Scan(&login)
	return login
}

func (p PGXPool) CheckLogin(login string) bool {
	exists := false
	p.pgxPool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM auth_schema.users WHERE login=$1);", login).Scan(exists)
	return exists
}

// =====

func (p PGXPool) InsertTieByIDAndChatIDAndRole(userid int, chatid int, role bool) error {
	_, err := p.pgxPool.Exec(context.Background(), "INSERT INTO chat_schema.ties (userid, chatid, role) VALUES ($1, $2, CASE WHEN $3 THEN 'admin'::chatrole ELSE 'listener'::chatrole END);", userid, chatid, role)
	return err
}

func (p PGXPool) DeleteTieByIDAndChatID(userid int, chatid int) error {
	_, err := p.pgxPool.Exec(context.Background(), "DELETE FROM chat_schema.ties WHERE userid=$1 AND chatid=$2;", userid, chatid)
	return err
}

func (p PGXPool) MarkChatAsDeletedByChatID(chatid int) error {
	_, err := p.pgxPool.Exec(context.Background(), "UPDATE chat_schema.groups SET deleted=TRUE WHERE chatid=$1;", chatid)
	return err
}

// =====

func (p PGXPool) Close() {
	p.pgxPool.Close()
}