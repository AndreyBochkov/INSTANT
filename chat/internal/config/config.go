package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

func New(path string) (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
