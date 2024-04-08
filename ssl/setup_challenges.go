package ssl

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
)

// Type is a string that identifies a particular challenge type and version of ACME challenge.
type ChallengeType string
type DNSProviderType string

const (
	HTTP          = ChallengeType("http")
	TLS           = ChallengeType("tls")
	DNS           = ChallengeType("dns")
	CloudflareDNS = DNSProviderType("cloudflare")
	GoogleDNS     = DNSProviderType("google")
)

func setupChallenges(ctx *SetupConfig, client *lego.Client) error {
	if ctx.ChallengeType == HTTP {
		ss, err := setupHTTPProvider(ctx)
		if err != nil {
			return err
		}
		err = client.Challenge.SetHTTP01Provider(ss)
		if err != nil {
			return err
		}
	} else if ctx.ChallengeType == TLS {
		ss, err := setupTLSProvider(ctx)
		if err != nil {
			return err
		}
		err = client.Challenge.SetTLSALPN01Provider(ss)
		if err != nil {
			return err
		}
	} else if ctx.ChallengeType == DNS {
		err := setupDNS(ctx, client)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no challenge selected. you must specify at least one challenge: `--http`, `--tls`, `--dns`")
	}
	return nil
}

func setupHTTPProvider(ctx *SetupConfig) (challenge.Provider, error) {
	if ctx.HTTPProvider == nil {
		return nil, fmt.Errorf("HTTPProvider is required")
	}
	iface := ctx.HTTPProvider.Port
	if !strings.Contains(iface, ":") {
		return nil, fmt.Errorf("the --http switch only accepts interface:port or :port for its argument")
	}

	host, port, err := net.SplitHostPort(iface)
	if err != nil {
		return nil, err
	}

	srv := http01.NewProviderServer(host, port)
	if header := ctx.HTTPProvider.ProxyHeader; header != "" {
		srv.SetProxyHeader(header)
	}
	return srv, nil
}

func setupTLSProvider(ctx *SetupConfig) (challenge.Provider, error) {
	switch {
	case ctx.TLSProvider.Port != "":
		iface := ctx.TLSProvider.Port
		if !strings.Contains(iface, ":") {
			return nil, fmt.Errorf("the --tls switch only accepts interface:port or :port for its argument")
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			return nil, err
		}

		return tlsalpn01.NewProviderServer(host, port), nil
	case ctx.ChallengeType == TLS:
		return tlsalpn01.NewProviderServer("", ""), nil
	default:
		return nil, fmt.Errorf("invalid HTTP challenge options")
	}
}

func setupDNS(ctx *SetupConfig, client *lego.Client) error {
	provider, err := NewDNSChallengeProviderByName(ctx.DNSprovider)
	if err != nil {
		return err
	}

	servers := ctx.DNSprovider.Resolvers

	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(len(servers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(ctx.DNSprovider.Resolvers))),
		dns01.CondOption(ctx.DNSprovider.DisableCp,
			dns01.DisableCompletePropagationRequirement()),
		dns01.CondOption(ctx.DNSprovider.DNSTimeout != 0,
			dns01.AddDNSTimeout(time.Duration(ctx.DNSprovider.DNSTimeout)*time.Second)),
	)
	if err != nil {
		return err
	}
	return nil
}
