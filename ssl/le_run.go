package ssl

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

const rootPathWarningMessage = `!!!! HEADS UP !!!!

Your account credentials have been saved in your Let's Encrypt
configuration directory at "%s".

You should make a secure backup of this folder now. This
configuration directory will also contain certificates and
private keys obtained from Let's Encrypt so making regular
backups of this folder is ideal.
`

func Run(ctx *SetupConfig) (map[string]string, error) {
	accountsStorage, err := NewAccountsStorage(ctx)
	if err != nil {
		return nil, err
	}

	account, client, err := setup(ctx, accountsStorage)
	if err != nil {
		return nil, err
	}
	err = setupChallenges(ctx, client)
	if err != nil {
		return nil, err
	}

	if account.Registration == nil {
		reg, err := register(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("could not complete registration\n\t%v", err)
		}

		account.Registration = reg
		if err = accountsStorage.Save(account); err != nil {
			return nil, err
		}

		fmt.Printf(rootPathWarningMessage, accountsStorage.GetRootPath())
	}

	certsStorage, err := NewCertificatesStorage(ctx)
	if err != nil {
		return nil, err
	}
	err = certsStorage.CreateRootFolder()
	if err != nil {
		return nil, err
	}
	cert, err := obtainCertificate(ctx, client)
	if err != nil {
		// Make sure to return a non-zero exit code if ObtainSANCertificate returned at least one error.
		// Due to us not returning partial certificate we can just exit here instead of at the end.
		return nil, fmt.Errorf("could not obtain certificates:\n\t%v", err)
	}

	certsStorage.SaveResource(cert)
	meta := map[string]string{
		"renewEnvAccountEmail": account.Email,
		"renewEnvCertDomain":   cert.Domain,
		"renewEnvCertPath":     certsStorage.GetFileName(cert.Domain, ".crt"),
		"renewEnvCertKeyPath":  certsStorage.GetFileName(cert.Domain, ".key"),
		"renewEnvCertPEMPath":  certsStorage.GetFileName(cert.Domain, ".pem"),
		"renewEnvCertPFXPath":  certsStorage.GetFileName(cert.Domain, ".pfx"),
	}
	return meta, nil
}

func handleTOS(ctx *SetupConfig, client *lego.Client) bool {
	// Check for a global accept override
	if ctx.AcceptTos {
		return true
	}

	reader := bufio.NewReader(os.Stdin)
	log.Printf("Please review the TOS at %s", client.GetToSURL())

	for {
		fmt.Println("Do you accept the TOS? Y/n")
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("could not read from console: ", err.Error())
			return false
		}

		text = strings.Trim(text, "\r\n")
		switch text {
		case "", "y", "Y":
			return true
		case "n", "N":
			return false
		default:
			fmt.Println("Your input was invalid. Please answer with one of Y/y, n/N or by pressing enter.")
		}
	}
}

func register(ctx *SetupConfig, client *lego.Client) (*registration.Resource, error) {
	accepted := handleTOS(ctx, client)
	if !accepted {
		return nil, fmt.Errorf("you did not accept the TOS. Unable to proceed")
	}

	if ctx.Eab {
		kid := ctx.Kid
		hmacEncoded := ctx.Hmac

		if kid == "" || hmacEncoded == "" {
			return nil, fmt.Errorf("requires arguments --kid and --hmac")
		}

		return client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: accepted,
			Kid:                  kid,
			HmacEncoded:          hmacEncoded,
		})
	}

	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func obtainCertificate(ctx *SetupConfig, client *lego.Client) (*certificate.Resource, error) {
	bundle := !ctx.NoBundle

	domains := ctx.Domains
	if len(domains) > 0 {
		// obtain a certificate, generating a new private key
		request := certificate.ObtainRequest{
			Domains:                        domains,
			Bundle:                         bundle,
			MustStaple:                     ctx.MustStaple,
			PreferredChain:                 ctx.PreferredChain,
			AlwaysDeactivateAuthorizations: ctx.AlwaysDeactivateAuthorizations,
		}
		return client.Certificate.Obtain(request)
	}

	// read the CSR
	csr, err := readCSRFile(ctx.Csr)
	if err != nil {
		return nil, err
	}

	// obtain a certificate for this CSR
	request := certificate.ObtainForCSRRequest{
		CSR: csr,
		// NotBefore:                      getTime(ctx, "not-before"),
		// NotAfter:                       getTime(ctx, "not-after"),
		Bundle:                         bundle,
		PreferredChain:                 ctx.PreferredChain,
		AlwaysDeactivateAuthorizations: ctx.AlwaysDeactivateAuthorizations,
	}

	return client.Certificate.ObtainForCSR(request)
}
