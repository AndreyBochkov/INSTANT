package config

type Config struct {
	Postgres	PGConfig	`yaml:"POSTGRES" env:"POSTGRES"`
	JWTKey		string		`yaml:"JWTKEY" env:"JWTKEY"`
	Port		int			`yaml:"PORT" env:"PORT"`
	Version		int			`yaml:"VERSION" env:"VERSION"`
}

type PGConfig struct {
	Host		string		`yaml:"POSTGRES_HOST" env:"POSTGRES_HOST" env-default:"localhost"`
	Port		uint16		`yaml:"POSTGRES_PORT" env:"POSTGRES_PORT"`
	Username	string		`yaml:"POSTGRES_USER" env:"POSTGRES_USER" env-default:"postgres"`
	Password	string		`yaml:"POSTGRES_PASS" env:"POSTGRES_PASS"`
	Database	string		`yaml:"POSTGRES_DB" env:"POSTGRES_DB" env-default:"postgres"`

	MinConns	int32 		`yaml:"POSTGRES_MIN_CONN" env:"POSTGRES_MIN_CONN" env-default:"5"`
	MaxConns	int32 		`yaml:"POSTGRES_MAX_CONN" env:"POSTGRES_MAX_CONN" env-default:"10"`
}