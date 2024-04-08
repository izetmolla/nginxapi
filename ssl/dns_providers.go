package ssl

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
)

type CloudFlareConfig struct {
	AuthEmail string
	AuthKey   string

	AuthToken string
	ZoneToken string

	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	HTTPClient         *http.Client
}

// NewDNSChallengeProviderByName Factory for DNS providers.
func NewDNSChallengeProviderByName(provider *DNSProvider) (challenge.Provider, error) {
	switch provider.Provider {
	case CloudflareDNS:
		return NewDNSProviderCloudflare(provider.CloudFlareProvider)
	case GoogleDNS:
		return nil, fmt.Errorf("soon")
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", provider.Provider)
	}
}

func NewDNSProviderCloudflare(c *CloudFlareProvider) (*cloudflare.DNSProvider, error) {
	if c.AuthEmail == "" {
		return nil, errors.New("AuthEmail is required")
	}
	cf := cloudflare.NewDefaultConfig()
	cf.AuthEmail = c.AuthEmail
	cf.AuthKey = c.AuthKey
	cf.AuthToken = c.AuthToken
	cf.ZoneToken = c.ZoneToken
	return cloudflare.NewDNSProviderConfig(cf)
}
