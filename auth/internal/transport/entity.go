package transport

import (
	"auth_service/pkg/postgres"
	"nhooyr.io/websocket"
)

type Transport struct {
	pool		postgres.PGXPool
	jwtKey		string
}

type RegisterRequest struct {
	Login		string	`json:"login"`
	Password	string	`json:"password"`
	Name		string	`json:"name"`
}

type LoginRequest struct {
	Login		string	`json:"login"`
	Password	string	`json:"password"`
}

type LoginResponse struct {
	Name		string	`json:"name"`
	Token		string	`json:"token"`
}