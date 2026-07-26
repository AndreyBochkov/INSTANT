package postgres

type Chat struct {
	ChatID		int			`json:"chatid"`
	Label		string		`json:"label"`
	Role		string		`json:"role"`
	Img			[]byte		`json:"img"`
}

type User struct {
	UserID		int			`json:"userid"`
	Login		string		`json:"login"`
	Img			[]byte		`json:"img"`
}

type Message struct {
	MessageID	int64		`json:"messageid"`
	Subid		int64		`json:"subid"`
	Ts			int64		`json:"ts"`
	Type		string		`json:"type"`
	Body		string		`json:"body"`
	Sender		int			`json:"sender"`
	Read		bool		`json:"read"`
}

type Alert struct {
	AlertID		int			`json:"alertid"`
	Ts			int64		`json:"ts"`
	Body		string		`json:"body"`
}

type Tie struct {
	UserID		int			`json:"userid"`
	ChatID		int			`json:"chatid"`
	Role		string		`json:"role"`
}

type Event struct {
	Eventid		int64		`json:"eventid"`
	Subid		int64		`json:"subid"`
	Ts			int64		`json:"ts"`
	Eventtype	string		`json:"type"`
	Chatid		int			`json:"chatid"`
	Userid		int			`json:"userid"`
	Content		[]byte		`json:"content"`
}