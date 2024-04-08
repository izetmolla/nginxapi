package ssl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/izetmolla/nginxapi/utils"
)

const (
	baseAccountsRootFolderName = "accounts"
	baseKeysFolderName         = "keys"
	accountFileName            = "account.json"
	maxRandomInt               = 128
	rpk                        = "RSA PRIVATE KEY"
	epk                        = "EC PRIVATE KEY"
)

// AccountsStorage A storage for account data.
//
// rootPath:
//
//	./.lego/accounts/
//	     │      └── root accounts directory
//	     └── "path" option
//
// rootUserPath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
//
// keysPath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/keys/
//	     │      │             │             │           └── root keys directory
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
//
// accountFilePath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/account.json
//	     │      │             │             │             └── account file
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
type AccountsStorage struct {
	userID          string
	rootPath        string
	rootUserPath    string
	keysPath        string
	accountFilePath string
	ctx             *SetupConfig
}

// NewAccountsStorage Creates a new AccountsStorage.
func NewAccountsStorage(ctx *SetupConfig) (*AccountsStorage, error) {
	// TODO: move to account struct? Currently MUST pass email.
	email := getEmail(ctx)

	serverURL, err := url.Parse(ctx.Server)
	if err != nil {
		return nil, err
	}

	rootPath := filepath.Join(ctx.AccountPath, baseAccountsRootFolderName)
	serverPath := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(serverURL.Host)
	accountsPath := filepath.Join(rootPath, serverPath)
	rootUserPath := filepath.Join(accountsPath, email)

	return &AccountsStorage{
		userID:          email,
		rootPath:        rootPath,
		rootUserPath:    rootUserPath,
		keysPath:        filepath.Join(rootUserPath, baseKeysFolderName),
		accountFilePath: filepath.Join(rootUserPath, accountFileName),
		ctx:             ctx,
	}, nil
}

func (s *AccountsStorage) ExistsAccountFilePath() bool {
	accountFile := filepath.Join(s.rootUserPath, accountFileName)
	if _, err := os.Stat(accountFile); os.IsNotExist(err) {
		return false
	} else if err != nil {
		fmt.Println("Error on ExistsAccountFilePath: ", err)
		return false
	}
	return true
}

func (s *AccountsStorage) GetRootPath() string {
	return s.rootPath
}

func (s *AccountsStorage) GetRootUserPath() string {
	return s.rootUserPath
}

func (s *AccountsStorage) GetUserID() string {
	return s.userID
}

func (s *AccountsStorage) Save(account *Account) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	return os.WriteFile(s.accountFilePath, jsonBytes, filePerm)
}

func (s *AccountsStorage) LoadAccount(privateKey crypto.PrivateKey) (*Account, error) {
	fileBytes, err := os.ReadFile(s.accountFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not load file for account %s: %v", s.userID, err)
	}

	var account Account
	err = json.Unmarshal(fileBytes, &account)
	if err != nil {
		return nil, fmt.Errorf("could not parse file for account %s: %v", s.userID, err)
	}

	account.key = privateKey

	if account.Registration == nil || account.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(s.ctx, privateKey)
		if err != nil {
			return nil, fmt.Errorf("could not load account for %s. Registration is nil: %#v", s.userID, err)
		}

		account.Registration = reg
		err = s.Save(&account)
		if err != nil {
			return nil, fmt.Errorf("could not save account for %s. Registration is nil: %#v", s.userID, err)
		}
	}

	return &account, nil
}

func (s *AccountsStorage) GetPrivateKey(keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	accKeyPath := filepath.Join(s.keysPath, s.userID+".key")

	if _, err := os.Stat(accKeyPath); os.IsNotExist(err) {
		log.Printf("No key found for account %s. Generating a %s key.", s.userID, keyType)
		err = s.createKeysFolder()
		if err != nil {
			return nil, err
		}

		privateKey, err := generatePrivateKey(accKeyPath, keyType)
		if err != nil {
			return nil, fmt.Errorf("could not generate RSA private account key for account %s: %v", s.userID, err)
		}

		log.Printf("Saved key to %s", accKeyPath)
		return privateKey, nil
	}

	privateKey, err := loadPrivateKey(accKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load RSA private key from file %s: %v", accKeyPath, err)
	}

	return privateKey, nil
}

func (s *AccountsStorage) createKeysFolder() error {
	if err := createNonExistingFolder(s.keysPath); err != nil {
		return fmt.Errorf("could not check/create directory for account %s: %v", s.userID, err)
	}
	return nil
}

func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case rpk:
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case epk:
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

// GenerateSelfSignedSSL generates a self-signed SSL certificate for the specified domain.
func generateSelfSignedSSL(privateKeyFile, certificateFile, domain, org string, keyType certcrypto.KeyType) error {
	privateKey, err := generatePrivateKey(privateKeyFile, keyType) // Adjust key type as needed
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), maxRandomInt))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{domain},
	}

	publicKey := privateKey.(crypto.Signer).Public()
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return err
	}
	certificateOut, err := os.Create(certificateFile)
	if err != nil {
		return err
	}
	defer certificateOut.Close()

	_ = pem.Encode(certificateOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})

	return nil
}
func saveCustomCertificates() error {
	return nil
}

func loadSelfSignedCertificate(file string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Decode PEM-encoded data
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func tryRecoverRegistration(ctx *SetupConfig, privateKey crypto.PrivateKey) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&Account{key: privateKey})
	config.CADirURL = ctx.Server
	config.UserAgent = getUserAgent(ctx)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func CreateLeHTTP01Conf(host, fp string) (pp string, err error) {
	if strings.Contains(host, ":") {
		pp = host
	} else {
		// Listen on a random available port
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", host))
		if err != nil {
			fmt.Println("Error:", err)
			return "0", err
		}
		defer listener.Close()

		// Get the address of the listener
		addr := listener.Addr().(*net.TCPAddr)
		pp = fmt.Sprintf("%s:%s", host, strconv.Itoa(addr.Port))
	}
	ctt := `location ~ "^/\.well-known/acme-challenge/([-_A-Za-z0-9]+)$" {
        proxy_pass http://%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }`

	var f *os.File
	f, err = os.Create(fp)
	if err != nil {
		defer f.Close()
		return "", err
	}
	if _, err = fmt.Fprintf(f, ctt, pp); err != nil {
		defer f.Close()
		return "", err
	} else {
		defer f.Close()
		if msg, err := utils.ReloadNginx(); err != nil {
			os.Remove(fp)
			return "", fmt.Errorf("%s %s", err.Error(), msg)
		} else {
			return pp, nil
		}
	}
}

func RemoveLeHTTP01Conf(fp string) {
	os.Remove(fp)
	_, _ = utils.ReloadNginx()
}
