package nginxapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/izetmolla/nginxapi/nginx"
	"github.com/izetmolla/nginxapi/ssl"
	"github.com/izetmolla/nginxapi/utils"
)

func setHTTPNginxFile(fp string, forceHTTPS bool, params ...any) (err error) {
	if forceHTTPS {
		return utils.StoreNginxFile(filepath.Join(fp, "nginx.conf"), `
server{
	listen %s;
	server_name %s;
    return 301 https://$host$request_uri;
	include %s/nginx.conf_*;
}`, params[1].(string), params[2].(string), params[5].(string))
	}
	return utils.StoreNginxFile(filepath.Join(fp, "nginx.conf"), `
server{
	%s
	listen %s;
	server_name %s;
	%s
	%s
	include %s/nginx.conf_*;
}`, params...)
}

func setHTTPSNginxFile(fp string, params ...any) (err error) {
	return utils.StoreNginxFile(filepath.Join(fp, "nginx.ssl.conf"), `
server{
	%s
	listen %s;
	server_name %s;
	%s
	%s
	%s
	include %s/nginx.conf_*;
}`, params...)
}

func includeOptions(options map[string]interface{}) string {
	var cf strings.Builder
	for directive, value := range options {
		cf.WriteString(fmt.Sprintf("\t%s %v;\n", directive, value))
	}
	return cf.String()
}

func includeListener(ip, port, other, srv string) string {
	if ip == "" {
		ip = "0.0.0.0"
	}
	if port == "" {
		if srv == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return fmt.Sprintf("%s:%s %s ", ip, port, other)
}

func includeSslConf(fp, dm, sslType string) string {
	if sslType == "" {
		sslType = "self"
	}
	var cc strings.Builder
	cc.WriteString(fmt.Sprintf("ssl_certificate %s;\n", filepath.Join(fp, "ssl", sslType, "certificates", fmt.Sprintf("%s.crt", dm))))
	cc.WriteString(fmt.Sprintf("ssl_certificate_key %s;\n", filepath.Join(fp, "ssl", sslType, "certificates", fmt.Sprintf("%s.key", dm))))
	return cc.String()
}

func formatLocations(locations []nginx.HostLocationData) string {
	var cc strings.Builder
	cc.WriteString("\n")
	for i := 0; i < len(locations); i++ {
		loc := locations[i]
		cc.WriteString(fmt.Sprintf("location %s {\n", loc.Name))
		for directive, value := range loc.Properties {
			cc.WriteString(fmt.Sprintf("\t%s %v;\n", directive, value))
		}
		cc.WriteString("}\n")
	}
	return cc.String()
}

func (ng *NGINX) checkAndUpdate(hostID string, dm []string, https bool, le *ssl.LetsEncrypt) (err error) {
	hp := filepath.Join(ng.ConfigPath, "hosts", hostID)
	if err := utils.InsertLineToFile(
		filepath.Join(ng.ConfigPath, "main.conf"),
		fmt.Sprintf("include %s/*.conf;", filepath.Join(hp, "config")),
	); err != nil {
		return err
	}

	if message, err := ng.Status(); err != nil {
		err = restoreCurrentConfig(filepath.Join(hp, hostID))
		if err != nil {
			return err
		}
		_ = removeBackupConfig(hp)
		_, err = ng.Reload()
		if err != nil {
			if err := utils.RemoveLineFromFile(filepath.Join(ng.ConfigPath, "main.conf"),
				fmt.Sprintf("include %s/*.conf;", filepath.Join(hp, "config")),
			); err != nil {
				_, _ = ng.Reload()
			}
		}
		return fmt.Errorf("%s", message)
	} else {
		if message, err := ng.Reload(); err != nil {
			return fmt.Errorf("%s %s", err.Error(), message)
		}
		if https && le != nil && ssl.IsLetEncryptExpired(filepath.Join(hp, fmt.Sprintf("config.%s", ng.ConfigExtension))) {
			go generateLESSL(hostID, dm, ng, le)
		}
		return nil
	}
}

func (nginx *NGINX) formatHostVariables(d *nginx.HostData) error {
	if len(d.ServerNames) == 0 {
		return errors.New("server names are required")
	}
	if d.LetsEncrypt != nil {
		if d.LetsEncrypt.ChallengeType == "" {
			return errors.New("letsencrypt need ChallengeType to work")
		}
		if d.LetsEncrypt.ChallengeType == ssl.TLS && d.LetsEncrypt.TLSProvider == nil {
			return errors.New("letsencrypt with ChallengeType tls need TLSProvider to work")
		}
		if d.LetsEncrypt.ChallengeType == ssl.DNS {
			if d.LetsEncrypt.DNSProvider == nil {
				return errors.New("letsencrypt with ChallengeType dns need DNSProvider to work")
			}
			if d.LetsEncrypt.DNSProvider.Provider == ssl.CloudflareDNS && d.LetsEncrypt.DNSProvider.CloudFlareProvider == nil {
				return errors.New("CloudFlareProvider need to be not null to work")
			}
		}
	}

	return nil
}

func backupCurrentConfig(pp string) (err error) {
	fp := filepath.Join(pp, "config")
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.conf")) {
		err = utils.CopyFile(filepath.Join(fp, "nginx.conf"), filepath.Join(fp, "nginx.back"))
	}
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.ssl.conf")) {
		err = utils.CopyFile(filepath.Join(fp, "nginx.ssl.conf"), filepath.Join(fp, "nginx.ssl.back"))
	}
	return err
}

func restoreCurrentConfig(pp string) (err error) {
	fp := filepath.Join(pp, "config")
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.back")) {
		err = utils.CopyFile(filepath.Join(fp, "nginx.back"), filepath.Join(fp, "nginx.conf"))
	}
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.ssl.back")) {
		err = utils.CopyFile(filepath.Join(fp, "nginx.ssl.back"), filepath.Join(fp, "nginx.ssl.conf"))
	}
	if err == nil {
		err = removeBackupConfig(pp)
	}
	return err
}
func removeBackupConfig(pp string) (err error) {
	fp := filepath.Join(pp, "config")
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.back")) {
		err = os.Remove(filepath.Join(fp, "nginx.back"))
	}
	if utils.IsExistOnDisk(filepath.Join(fp, "nginx.ssl.back")) {
		err = os.Remove(filepath.Join(fp, "nginx.ssl.back"))
	}
	return err
}

func (ng *NGINX) hostDataToObject(data *nginx.HostData) nginx.HostData {
	return nginx.HostData{
		HostID:      data.HostID,
		ServerNames: data.ServerNames,
		Locations:   data.Locations,
		HTTPS:       data.HTTPS,
		ForceHTTPS:  data.ForceHTTPS,
		ListenIP:    data.ListenIP,
		ListenPORT:  data.ListenPORT,
		LetsEncrypt: data.LetsEncrypt,
	}
}

func strOrDefault(c, d string) string {
	if c == "" {
		return d
	}
	return c
}
