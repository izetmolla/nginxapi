package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const filePerm os.FileMode = 0o600

type SetupConfig struct {
	ConfigPath                     string
	AccountPath                    string
	Path                           string
	Server                         string
	Domains                        []string
	CertTimeout                    int
	HTTPTimeout                    int
	KeyType                        string
	Email                          string
	UserAgent                      string
	UserAgentVersion               string
	Eab                            bool
	AcceptTos                      bool
	Kid                            string
	Hmac                           string
	NoBundle                       bool
	MustStaple                     bool
	PreferredChain                 string
	AlwaysDeactivateAuthorizations bool
	Csr                            string
	Filename                       string
	Pfx                            bool
	Pem                            bool
	PfxPass                        string
	PfxFormat                      string
	ChallengeType                  ChallengeType
	HTTPProvider                   *HTTPProvider
	TLSProvider                    *TLSProvider
	DNSprovider                    *DNSProvider
	AirEnable                      bool
	Days                           int
	AriWaitToRenewDuration         time.Duration
	ReuseKey                       bool
	NoRandomSleep                  bool
	Reason                         uint
	Keep                           bool
}

func setup(ctx *SetupConfig, accountsStorage *AccountsStorage) (*Account, *lego.Client, error) {
	keyType, err := getKeyType(ctx)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := accountsStorage.GetPrivateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	var account *Account
	if accountsStorage.ExistsAccountFilePath() {
		acc, err := accountsStorage.LoadAccount(privateKey)
		if err != nil {
			return nil, nil, err
		}
		account = acc
	} else {
		account = &Account{Email: accountsStorage.GetUserID(), key: privateKey}
	}

	client, err := newClient(ctx, account, keyType)
	if err != nil {
		return nil, nil, err
	}

	return account, client, nil
}

func newClient(ctx *SetupConfig, acc registration.User, keyType certcrypto.KeyType) (*lego.Client, error) {
	config := lego.NewConfig(acc)
	config.CADirURL = ctx.Server

	config.Certificate = lego.CertificateConfig{
		KeyType: keyType,
		Timeout: time.Duration(ctx.CertTimeout) * time.Second,
	}
	config.UserAgent = getUserAgent(ctx)

	if ctx.HTTPTimeout != 0 {
		config.HTTPClient.Timeout = time.Duration(ctx.HTTPTimeout) * time.Second
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %v", err)
	}

	if client.GetExternalAccountRequired() && !ctx.Eab {
		return nil, fmt.Errorf("server requires external account binding. use --eab with --kid and --hmac")
	}

	return client, nil
}

// getKeyType the type from which private keys should be generated.
func getKeyType(ctx *SetupConfig) (certcrypto.KeyType, error) {
	switch strings.ToUpper(ctx.KeyType) {
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA3072":
		return certcrypto.RSA3072, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	}

	return "", fmt.Errorf("unsupported KeyType: %s", ctx.KeyType)
}

func getEmail(ctx *SetupConfig) string {
	email := ctx.Email
	if email == "" {
		fmt.Println("You have to pass an account (email address) to the program using --email or -m")
	}
	return email
}

func getUserAgent(ctx *SetupConfig) string {
	return strings.TrimSpace(fmt.Sprintf("%s lego-cli/%s", ctx.UserAgent, ctx.UserAgentVersion))
}

func createNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}

func readCSRFile(filename string) (*x509.CertificateRequest, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	raw := bytes

	// see if we can find a PEM-encoded CSR
	var p *pem.Block
	rest := bytes
	for {
		// decode a PEM block
		p, rest = pem.Decode(rest)

		// did we fail?
		if p == nil {
			break
		}

		// did we get a CSR?
		if p.Type == "CERTIFICATE REQUEST" || p.Type == "NEW CERTIFICATE REQUEST" {
			raw = p.Bytes
		}
	}

	// no PEM-encoded CSR
	// assume we were given a DER-encoded ASN.1 CSR
	// (if this assumption is wrong, parsing these bytes will fail)
	return x509.ParseCertificateRequest(raw)
}
