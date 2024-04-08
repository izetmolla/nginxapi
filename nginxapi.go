package nginxapi

import (
	"path/filepath"

	"github.com/izetmolla/nginxapi/ssl"
	"github.com/izetmolla/nginxapi/utils"
	"gorm.io/gorm/logger"
)

type Config struct {
	Org             string
	ConfigPath      string
	Logger          logger.Interface
	ConfigExtension string
	LetsEncrypt     *ssl.LetsEncrypt
}

type NGINX struct {
	*Config
	Error error
}

func New(conf *Config) (nginx *NGINX, err error) {
	config := conf
	if config.Logger == nil {
		config.Logger = logger.Default
	}
	if config.Org == "" {
		config.Org = "Proxy Manager"
	}
	if config.ConfigPath == "" {
		config.ConfigPath = "/etc/nginx/config.pm"
	}
	if config.ConfigExtension == "" {
		config.ConfigExtension = "yaml"
	}

	nginx = &NGINX{Config: config}

	utils.CreateCustomDirectories(config.ConfigPath)
	return
}

func (nginx *NGINX) configPath(cp ...string) string {
	return filepath.Join(nginx.ConfigPath, filepath.Join(cp...))
}
