package logger

import (
	"context"
	"go.uber.org/zap"
	"fmt"
	"os"
)

const (
	Key = "logger"
	RequestIDKey = "request_id"
)

var (
	serviceField = zap.String("service", "Auth_service")
)

type Logger struct {
	l *zap.Logger
}

func New(ctx context.Context) (context.Context, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, Key, &Logger{logger})
	return ctx, nil
}

func GetLoggerFromCtx(ctx context.Context) *Logger {
	return ctx.Value(Key).(*Logger)
}

func Info(ctx context.Context, msg string, fields ...zap.Field) {
	if ctx.Value(Key) != nil {
		if ctx.Value(RequestIDKey) != nil {
			fields = append(fields, zap.String(RequestIDKey, ctx.Value(RequestIDKey).(string)))
		}
		fields = append(fields, serviceField)
		GetLoggerFromCtx(ctx).l.Info(msg, fields...)
		return
	}
	fmt.Println(msg)
}

func Fatal(ctx context.Context, msg string, fields ...zap.Field) {
	if ctx.Value(Key) != nil {
		if ctx.Value(RequestIDKey) != nil {
			fields = append(fields, zap.String(RequestIDKey, ctx.Value(RequestIDKey).(string)))
		}
		fields = append(fields, serviceField)
		GetLoggerFromCtx(ctx).l.Fatal(msg, fields...)
		return
	}
	fmt.Println(msg)
	os.Exit(1)
}

func Warn(ctx context.Context, msg string, fields ...zap.Field) {
	if ctx.Value(Key) != nil {
		if ctx.Value(RequestIDKey) != nil {
			fields = append(fields, zap.String(RequestIDKey, ctx.Value(RequestIDKey).(string)))
		}
		fields = append(fields, serviceField)
		GetLoggerFromCtx(ctx).l.Warn(msg, fields...)
		return
	}
	fmt.Println(msg)
}