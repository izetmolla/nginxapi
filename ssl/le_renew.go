package ssl

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/mattn/go-isatty"
)

const (
	renewEnvAccountEmail = "LEGO_ACCOUNT_EMAIL"
	renewEnvCertDomain   = "LEGO_CERT_DOMAIN"
	renewEnvCertPath     = "LEGO_CERT_PATH"
	renewEnvCertKeyPath  = "LEGO_CERT_KEY_PATH"
	renewEnvCertPEMPath  = "LEGO_CERT_PEM_PATH"
	renewEnvCertPFXPath  = "LEGO_CERT_PFX_PATH"
	daynr                = 24.0
)

func Renew(ctx *SetupConfig) (map[string]interface{}, error) {
	accountsStorage, err := NewAccountsStorage(ctx)
	if err != nil {
		return nil, err
	}
	account, client, err := setup(ctx, accountsStorage)
	if err != nil {
		return nil, err
	}
	if err = setupChallenges(ctx, client); err != nil {
		return nil, err
	}

	if account.Registration == nil {
		return nil, fmt.Errorf("account %s is not registered. Use 'run' to register a new account", account.Email)
	}

	certsStorage, err := NewCertificatesStorage(ctx)
	if err != nil {
		return nil, err
	}
	bundle := !ctx.NoBundle

	meta := map[string]string{renewEnvAccountEmail: account.Email}

	// CSR
	if ctx.Csr != "" {
		return nil, renewForCSR(ctx, client, certsStorage, bundle, meta)
	}

	// Domains
	return nil, renewForDomains(ctx, client, certsStorage, bundle, meta)
}

func renewForDomains(ctx *SetupConfig, client *lego.Client, certsStorage *CertificatesStorage, bundle bool, meta map[string]string) error {
	domains := ctx.Domains
	domain := domains[0]

	// load the cert resource from files.
	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	certificates, err := certsStorage.ReadCertificate(domain, ".crt")
	if err != nil {
		return fmt.Errorf("error while loading the certificate for domain %s\n\t%v", domain, err)
	}

	cert := certificates[0]

	var ariRenewalTime *time.Time
	if ctx.AirEnable {
		ariRenewalTime = getARIRenewalTime(ctx, cert, domain, client)
		if ariRenewalTime != nil {
			now := time.Now().UTC()
			// Figure out if we need to sleep before renewing.
			if ariRenewalTime.After(now) {
				log.Infof("[%s] Sleeping %s until renewal time %s", domain, ariRenewalTime.Sub(now), ariRenewalTime)
				time.Sleep(ariRenewalTime.Sub(now))
			}
		}
	}

	if ariRenewalTime == nil && !needRenewal(cert, domain, ctx.Days) {
		return nil
	}

	// This is just meant to be informal for the user.
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	log.Infof("[%s] acme: Trying renewal with %d hours remaining", domain, int(timeLeft.Hours()))

	certDomains := certcrypto.ExtractDomains(cert)

	var privateKey crypto.PrivateKey
	if ctx.ReuseKey {
		keyBytes, errR := certsStorage.ReadFile(domain, ".key")
		if errR != nil {
			return fmt.Errorf("error while loading the private key for domain %s\n\t%v", domain, errR)
		}

		privateKey, errR = certcrypto.ParsePEMPrivateKey(keyBytes)
		if errR != nil {
			return errR
		}
	}

	// https://github.com/go-acme/lego/issues/1656
	// https://github.com/certbot/certbot/blob/284023a1b7672be2bd4018dd7623b3b92197d4b0/certbot/certbot/_internal/renewal.py#L435-L440
	if !isatty.IsTerminal(os.Stdout.Fd()) && !ctx.NoRandomSleep {
		// https://github.com/certbot/certbot/blob/284023a1b7672be2bd4018dd7623b3b92197d4b0/certbot/certbot/_internal/renewal.py#L472
		const jitter = 8 * time.Minute
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		sleepTime := time.Duration(rnd.Int63n(int64(jitter)))

		log.Infof("renewal: random delay of %s", sleepTime)
		time.Sleep(sleepTime)
	}

	request := certificate.ObtainRequest{
		Domains:    merge(certDomains, domains),
		PrivateKey: privateKey,
		MustStaple: ctx.MustStaple,
		// NotBefore:                      getTime(ctx, "not-before"),
		// NotAfter:                       getTime(ctx, "not-after"),
		Bundle:                         bundle,
		PreferredChain:                 ctx.PreferredChain,
		AlwaysDeactivateAuthorizations: ctx.AlwaysDeactivateAuthorizations,
	}

	if ctx.AirEnable {
		request.ReplacesCertID, err = certificate.MakeARICertID(cert)
		if err != nil {
			return fmt.Errorf("error while construction the ARI CertID for domain %s\n\t%v", domain, err)
		}
	}

	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	certsStorage.SaveResource(certRes)

	meta[renewEnvCertDomain] = domain
	meta[renewEnvCertPath] = certsStorage.GetFileName(domain, ".crt")
	meta[renewEnvCertKeyPath] = certsStorage.GetFileName(domain, ".key")
	meta[renewEnvCertPEMPath] = certsStorage.GetFileName(domain, ".pem")
	meta[renewEnvCertPFXPath] = certsStorage.GetFileName(domain, ".pfx")
	return nil
}

func renewForCSR(ctx *SetupConfig, client *lego.Client, certsStorage *CertificatesStorage, bundle bool, meta map[string]string) error {
	csr, err := readCSRFile(ctx.Csr)
	if err != nil {
		return err
	}

	domain, err := certcrypto.GetCSRMainDomain(csr)
	if err != nil {
		return err
	}

	// load the cert resource from files.
	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	certificates, err := certsStorage.ReadCertificate(domain, ".crt")
	if err != nil {
		return fmt.Errorf("error while loading the certificate for domain %s\n\t%v", domain, err)
	}

	cert := certificates[0]

	var ariRenewalTime *time.Time
	if ctx.AirEnable {
		ariRenewalTime = getARIRenewalTime(ctx, cert, domain, client)
		if ariRenewalTime != nil {
			now := time.Now().UTC()
			// Figure out if we need to sleep before renewing.
			if ariRenewalTime.After(now) {
				log.Infof("[%s] Sleeping %s until renewal time %s", domain, ariRenewalTime.Sub(now), ariRenewalTime)
				time.Sleep(ariRenewalTime.Sub(now))
			}
		}
	}

	if ariRenewalTime == nil && !needRenewal(cert, domain, ctx.Days) {
		return nil
	}

	// This is just meant to be informal for the user.
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	log.Infof("[%s] acme: Trying renewal with %d hours remaining", domain, int(timeLeft.Hours()))

	request := certificate.ObtainForCSRRequest{
		CSR: csr,
		// NotBefore:                      getTime(ctx, "not-before"),
		// NotAfter:                       getTime(ctx, "not-after"),
		Bundle:                         bundle,
		PreferredChain:                 ctx.PreferredChain,
		AlwaysDeactivateAuthorizations: ctx.AlwaysDeactivateAuthorizations,
	}

	if ctx.AirEnable {
		request.ReplacesCertID, err = certificate.MakeARICertID(cert)
		if err != nil {
			return fmt.Errorf("error while construction the ARI CertID for domain %s\n\t%v", domain, err)
		}
	}

	certRes, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		return err
	}

	certsStorage.SaveResource(certRes)

	meta[renewEnvCertDomain] = domain
	meta[renewEnvCertPath] = certsStorage.GetFileName(domain, ".crt")
	meta[renewEnvCertKeyPath] = certsStorage.GetFileName(domain, ".key")
	return nil
}

func needRenewal(x509Cert *x509.Certificate, domain string, days int) bool {
	if x509Cert.IsCA {
		fmt.Printf("[%s] Certificate bundle starts with a CA certificate", domain)
		return false
	}

	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / daynr)
		if notAfter > days {
			log.Printf("[%s] The certificate expires in %d days, the number of days defined to perform the renewal is %d: no renewal.",
				domain, notAfter, days)
			return false
		}
	}

	return true
}

// getARIRenewalTime checks if the certificate needs to be renewed using the renewalInfo endpoint.
func getARIRenewalTime(ctx *SetupConfig, cert *x509.Certificate, domain string, client *lego.Client) *time.Time {
	if cert.IsCA {
		fmt.Printf("[%s] Certificate bundle starts with a CA certificate", domain)
		return nil
	}

	renewalInfo, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			// The server does not advertise a renewal info endpoint.
			log.Warnf("[%s] acme: %v", domain, err)
			return nil
		}
		log.Warnf("[%s] acme: calling renewal info endpoint: %v", domain, err)
		return nil
	}

	now := time.Now().UTC()
	renewalTime := renewalInfo.ShouldRenewAt(now, ctx.AriWaitToRenewDuration)
	if renewalTime == nil {
		log.Infof("[%s] acme: renewalInfo endpoint indicates that renewal is not needed", domain)
		return nil
	}
	log.Infof("[%s] acme: renewalInfo endpoint indicates that renewal is needed", domain)

	if renewalInfo.ExplanationURL != "" {
		log.Infof("[%s] acme: renewalInfo endpoint provided an explanation: %s", domain, renewalInfo.ExplanationURL)
	}

	return renewalTime
}

func merge(prevDomains, nextDomains []string) []string {
	for _, next := range nextDomains {
		var found bool
		for _, prev := range prevDomains {
			if prev == next {
				found = true
				break
			}
		}
		if !found {
			prevDomains = append(prevDomains, next)
		}
	}
	return prevDomains
}
