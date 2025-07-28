package postgres

import (
	"time"
)

type Chat struct {
	ChatID		int			`json:"chatid"`
	User2		int			`json:"user2"`
	Label		string		`json:"label"`
}

type User struct {
	UserID		int			`json:"userid"`
	Login		string		`json:"login"`
	Name		string		`json:"name"`
}

type Message struct {
	MessageID	int64		`json:"messageid"`
	Ts			time.Time	`json:"ts"`
	Body		string		`json:"body"`
	Mine		bool		`json:"mine"`
}