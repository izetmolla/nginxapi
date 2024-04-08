package ssl

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/izetmolla/nginxapi/utils"
)

const (
	SSLTypeLocal = "self"
	// LEDirectoryProduction URL to the Let's Encrypt production.
	LEDirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
	// LEDirectoryStaging URL to the Let's Encrypt staging.
	LEDirectoryStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Type is a string that identifies a particular challenge type and version of ACME challenge.
type Challenge string

func GetLastSSLType(hostPath string) string {
	cc, err := utils.GetContentByParam(
		filepath.Join(hostPath, "config", "nginx.ssl.conf"),
		"ssl_certificate_key",
	)
	if err != nil {
		return SSLTypeLocal
	}
	arrOfStr := strings.Split(cc, "/")
	if len(arrOfStr) > 3 {
		return arrOfStr[len(arrOfStr)-3]
	}
	return SSLTypeLocal
}

func GetLetsEncryptExpirationDate(filePath string) time.Time {
	data, err := utils.Unmarshal(filePath)
	if err != nil {
		return time.Now()
	}
	if data["ssl_expire_at"] != nil {
		if parsedTime, err := time.Parse(time.RFC3339Nano, data["ssl_expire_at"].(string)); err != nil {
			return time.Now()
		} else {
			return parsedTime
		}
	}
	return time.Now()
}

func IsLetEncryptExpired(filePath string) bool {
	exp := GetLetsEncryptExpirationDate(filePath)
	return time.Now().After(exp.Add(-60 * time.Minute))
}

func ChangeSSLFolder(confPath, hostID, dm, sslType string) error {
	sslFile := filepath.Join(confPath, "hosts", hostID, "config", "nginx.ssl.conf")
	ss := filepath.Join(confPath, "hosts", hostID, "ssl", sslType, "certificates")
	if err := utils.ChangeConfigByParam(sslFile, "ssl_certificate ", filepath.Join(ss, fmt.Sprintf("%s.crt", dm))); err != nil {
		return err
	}
	if err := utils.ChangeConfigByParam(sslFile, "ssl_certificate_key ", filepath.Join(ss, fmt.Sprintf("%s.key", dm))); err != nil {
		return err
	}
	return nil
}

func getTime(name string) time.Time {
	// value := ctx.Timestamp(name)
	// if value == nil {
	fmt.Println("title:", name)
	return time.Time{}
	// }
	// return *value
}

func CheckForSelfSSL(fps, domain string) bool {
	return utils.IsExistOnDisk(fps, "ssl", "self", "certificates", fmt.Sprintf("%s.crt", domain))
}

func GenerateSelfSSL(domain, fp, org string) error {
	p := filepath.Join(fp, "ssl", "self", "certificates")
	utils.MakeDirs(p)
	return generateSelfSignedSSL(
		filepath.Join(p, fmt.Sprintf("%s.key", domain)),
		filepath.Join(p, fmt.Sprintf("%s.crt", domain)),
		domain,
		org,
		certcrypto.RSA2048,
	)
}
