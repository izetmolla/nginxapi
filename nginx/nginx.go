package nginx

import "github.com/izetmolla/nginxapi/ssl"

type HostData struct {
	HostID      string
	ServerNames []string
	Locations   []HostLocationData
	HTTPS       bool
	ForceHTTPS  bool
	ListenIP    string
	ListenPORT  string
	LetsEncrypt *ssl.LetsEncrypt
}

type HostLocationData struct {
	Name       string
	Properties map[string]interface{}
}
