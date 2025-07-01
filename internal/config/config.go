package config

import (
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env        string `yaml:"env" env-default:"local"`
	StorageURL string `yaml:"storage_url" env:"POSTGRES_URL" env-required:"true"`
	HTTPServer `yaml:"http_server"`
	JWT        `yaml:"jwt"`
	WebhookURL string `yaml:"webhook_url" env:"WEBHOOK_URL" env-required:"true"`
}

type HTTPServer struct {
	Host        string        `yaml:"host" env-default:""`
	Port        string        `yaml:"port" env:"APP_PORT" env-required:"true"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

type JWT struct {
	Secret     string        `yaml:"secret" env:"JWT_SECRET" env-required:"true"`
	AccessTTL  time.Duration `yaml:"access_ttl" env-default:"15m"`
	RefreshTTL time.Duration `yaml:"refresh_ttl" env-default:"72h"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		if _, err := os.Stat("config/local.yaml"); err == nil {
			configPath = "config/local.yaml"
		} else {
			log.Fatal("CONFIG_PATH is not set and config/local.yaml not found")
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("config file does not exist: %s", configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("cannot read config: %s", err)
	}

	if err := cleanenv.ReadEnv(&cfg); err != nil {
		log.Fatalf("cannot read environment variables: %s", err)
	}

	return &cfg
}
