package nginxapi

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/izetmolla/nginxapi/ssl"
	"github.com/izetmolla/nginxapi/utils"
)

func generateLESSL(hostID string, dm []string, ng *NGINX, le *ssl.LetsEncrypt) (err error) {
	hPath := filepath.Join(ng.ConfigPath, "hosts", hostID)
	if le.Email == "" {
		if ng.LetsEncrypt == nil {
			fmt.Println("LetsEncrypt is required on global config")
			return errors.New("LetsEncrypt is required on global config")
		}
		if ng.LetsEncrypt.Email == "" {
			fmt.Print("email must be available at Global letsencrypt config")
			return errors.New("email must be available at Global letsencrypt config")
		}
		le.Email = ng.LetsEncrypt.Email
	}
	if le.PfxFormat == "" {
		le.PfxFormat = "SHA256"
	}
	if le.ChallengeType == ssl.HTTP {
		if le.HTTPProvider != nil {
			_, _ = ssl.CreateLeHTTP01Conf(le.HTTPProvider.Port, filepath.Join(hPath, "config", "nginx.conf_letsencrypt"))
		} else {
			if port, err := ssl.CreateLeHTTP01Conf(
				"localhost",
				filepath.Join(hPath, "config", "nginx.conf_letsencrypt"),
			); err != nil {
				fmt.Println("ee: ", err)
				return err
			} else {
				le.HTTPProvider = &ssl.HTTPProvider{
					Port: port,
				}
			}
		}
	}
	if files, err := ssl.Run(&ssl.SetupConfig{
		ConfigPath:    ng.ConfigPath,
		Domains:       dm,
		ChallengeType: le.ChallengeType,
		AccountPath:   strOrDefault(le.AccountPath, filepath.Join(ng.ConfigPath, "letsencrypt")),
		Path:          strOrDefault(le.CertificatesPath, filepath.Join(hPath, "ssl", "letsencrypt")),
		Server:        strOrDefault(le.Server, ssl.LEDirectoryProduction),
		Email:         le.Email,
		KeyType:       strOrDefault(le.KeyType, "RSA4096"),
		DNSprovider:   le.DNSProvider,
		HTTPProvider:  le.HTTPProvider,
		TLSProvider:   le.TLSProvider,
		PfxFormat:     strOrDefault(le.PfxFormat, "SHA256"),
		AcceptTos:     true,
	}); err != nil {
		return err
	} else {
		if err := changeNnginxSSLFiles(hPath, files); err != nil {
			return err
		}
	}
	_, _ = utils.ReloadNginx()
	_ = utils.SetConfigData(filepath.Join(ng.ConfigPath, "hosts", hostID), ng.ConfigExtension, map[string]interface{}{
		"ssl_expire_at": time.Now().AddDate(0, 0, 89),
	})
	if le.ChallengeType == ssl.HTTP {
		ssl.RemoveLeHTTP01Conf(filepath.Join(hPath, "config", "nginx.conf_letsencrypt"))
	}
	return nil
}

func changeNnginxSSLFiles(hp string, files map[string]string) error {
	sslFile := filepath.Join(hp, "config", "nginx.ssl.conf")
	if err := utils.ChangeConfigByParam(sslFile, "ssl_certificate ", files["renewEnvCertPath"]); err != nil {
		return err
	}
	if err := utils.ChangeConfigByParam(sslFile, "ssl_certificate_key ", files["renewEnvCertKeyPath"]); err != nil {
		return err
	}
	return nil
}

func (ng *NGINX) updateSSLType(hostID, dm, sslType string) error {
	fp := filepath.Join(ng.ConfigPath, "hosts", hostID)
	if err := utils.ChangeConfigByParam(
		filepath.Join(fp, "config", "nginx.ssl.conf"),
		"ssl_certificate ",
		filepath.Join(fp, "ssl", sslType, "certificates", fmt.Sprintf("%s.crt", dm)),
	); err != nil {
		return err
	}
	if err := utils.ChangeConfigByParam(
		filepath.Join(fp, "config", "nginx.ssl.conf"),
		"ssl_certificate ",
		filepath.Join(fp, "ssl", sslType, "certificates", fmt.Sprintf("%s.key", dm)),
	); err != nil {
		return err
	}
	return nil
}
