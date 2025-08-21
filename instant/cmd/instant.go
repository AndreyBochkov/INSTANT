package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"errors"
	"time"
	"syscall"
	"strconv"

	"go.uber.org/zap"

	"instant_service/pkg/logger"
	"instant_service/internal/config"
	"instant_service/pkg/postgres"
	"instant_service/internal/transport"
)

func main() {
	ctx, err := logger.New(context.Background())
	if err != nil {
		fmt.Printf("Failed to start logger: %w\n", err)
		return
	}
	logger.Info(ctx, "Logger started")

	logger.Info(ctx, "Loading config...")
	cfg, err := config.New("./config/config.env")
	if err != nil {
		logger.Fatal(ctx, "Failed to load config", zap.Error(err))
	}
	logger.Info(ctx, "INSTANT PROTOCOL VERSION: " + strconv.Itoa(cfg.Version))

	logger.Info(ctx, "Connecting to the database...")
	pool, err := postgres.New(ctx, cfg.Postgres, "./db/migrations")
	if err != nil {
		logger.Fatal(ctx, "Failed to connect to the database", zap.Error(err))
	}

	logger.Info(ctx, "Setting up transport layer...")
	t := transport.New(pool, cfg.Version, cfg.RotationInterval)
	mux := http.NewServeMux()
	mux.Handle("/instant/", transport.MiddlewareHandler(t.MainHandler))
	mux.Handle("/sync/", transport.MiddlewareHandler(t.SyncHandler))
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
	}
	go func() {
		logger.Info(ctx, "Starting Server...")
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(ctx, "Failed to serve", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	logger.Info(ctx, "Ready for graceful shutdown. Press CTRL+C to execute.")
	<-quit
	logger.Info(ctx, "Gracefully shutting down...")
	timeoutctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server.Shutdown(timeoutctx)
	logger.Info(ctx, "Server gracefully stopped.")
	pool.Close()
	logger.Info(ctx, "Database connection stopped.")
}