package postgres

type Chat struct {
	ChatID		int			`json:"chatid"`
	Label		string		`json:"label"`
	CanSend		bool		`json:"cansend"`
}

type User struct {
	UserID		int			`json:"userid"`
	Login		string		`json:"login"`
}

type Message struct {
	MessageID	int64		`json:"messageid"`
	Ts			int64		`json:"ts"`
	Body		string		`json:"body"`
	Sender		int			`json:"sender"`
}

type Alert struct {
	AlertID		int			`json:"alertid"`
	Ts			int64		`json:"ts"`
	Body		string		`json:"body"`
}

type Tie struct {
	UserID		int		`json:"userid"`
	ChatID		int		`json:"chatid"`
	CanSend		bool	`json:"cansend"`
}