package ssl

import (
	"net/http"
	"time"
)

type CloudFlareProvider struct {
	AuthEmail string
	AuthKey   string

	AuthToken string
	ZoneToken string

	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	HTTPClient         *http.Client
}

type HTTPProvider struct {
	Port        string
	ProxyHeader string
}

type TLSProvider struct {
	Port string
}

type DNSProvider struct {
	Provider           DNSProviderType
	CloudFlareProvider *CloudFlareProvider
	Resolvers          []string
	DisableCp          bool
	DNSTimeout         int
}

type LetsEncrypt struct {
	ChallengeType    ChallengeType
	HTTPProvider     *HTTPProvider
	TLSProvider      *TLSProvider
	DNSProvider      *DNSProvider
	Email            string
	PfxFormat        string
	KeyType          string
	Server           string
	CertificatesPath string
	AccountPath      string
	RestartNginx     bool
}
