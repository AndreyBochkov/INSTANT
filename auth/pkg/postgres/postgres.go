package postgres

import (
	"fmt"
	"context"
	"errors"
	"auth_service/internal/config"
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

func (p PGXPool) Close() {
	p.pgxPool.Close()
}