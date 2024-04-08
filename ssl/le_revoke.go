package ssl

import (
	"fmt"

	"github.com/go-acme/lego/v4/log"
)

func Revoke(ctx *SetupConfig) error {
	accountsStorage, err := NewAccountsStorage(ctx)
	if err != nil {
		return err
	}
	acc, client, err := setup(ctx, accountsStorage)
	if err != nil {
		return err
	}

	if acc.Registration == nil {
		return fmt.Errorf("account %s is not registered. Use 'run' to register a new account", acc.Email)
	}

	certsStorage, err := NewCertificatesStorage(ctx)
	if err != nil {
		return err
	}
	err = certsStorage.CreateRootFolder()
	if err != nil {
		return err
	}

	for _, domain := range ctx.Domains {
		log.Printf("Trying to revoke certificate for domain %s", domain)

		certBytes, err := certsStorage.ReadFile(domain, ".crt")
		if err != nil {
			return fmt.Errorf("error while revoking the certificate for domain %s\n\t%v", domain, err)
		}

		reason := ctx.Reason

		err = client.Certificate.RevokeWithReason(certBytes, &reason)
		if err != nil {
			return fmt.Errorf("error while revoking the certificate for domain %s\n\t%v", domain, err)
		}

		log.Println("Certificate was revoked.")

		if ctx.Keep {
			return nil
		}

		certsStorage.CreateArchiveFolder()

		err = certsStorage.MoveToArchive(domain)
		if err != nil {
			return err
		}

		log.Println("Certificate was archived for domain:", domain)
	}

	return nil
}
