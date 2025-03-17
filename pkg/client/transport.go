package client

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"go.uber.org/ratelimit"
)

const (

	// https://docs.snyk.io/snyk-api/snyk-rest-api-overview#rate-limiting
	RateLimitREST int64 = 1620

	// https://docs.snyk.io/snyk-api/using-snyk-api-articles/snyk-api-rate-limits
	RateLimitV1 int64 = 2000
)

type SnykAPITransport struct {
	Transport           http.RoundTripper
	AuthorizationHeader string
	Version             string
	leakyBucketV1       ratelimit.Limiter
	leakyBucketREST     ratelimit.Limiter
}

func NewSnykAPITransport(authorizationHeader, version string, skipVerifyTLS bool) *SnykAPITransport {
	return &SnykAPITransport{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerifyTLS, // #nosec G402
			},
			Proxy: http.ProxyFromEnvironment,
		},
		AuthorizationHeader: authorizationHeader,
		Version:             version,
		leakyBucketV1:       ratelimit.New(int(RateLimitV1), ratelimit.Per(60*time.Second)),
		leakyBucketREST:     ratelimit.New(int(RateLimitREST), ratelimit.Per(60*time.Second)),
	}
}

func (snyk *SnykAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	snykRequest := req.Clone(req.Context())
	snykRequest.Header.Set("Authorization", snyk.AuthorizationHeader)
	if strings.HasPrefix(req.URL.Path, "/rest") {
		if !snykRequest.URL.Query().Has("version") {
			params := req.URL.Query()
			params.Add("version", snyk.Version)
			snykRequest.URL.RawQuery = params.Encode()
		}
		snykRequest.Header.Set("Content-Type", "application/vnd.api+json")
		snyk.leakyBucketREST.Take()
	} else {
		snykRequest.Header.Set("Content-Type", "application/json")
		snyk.leakyBucketV1.Take()
	}
	if snyk.Transport == nil {
		return http.DefaultTransport.RoundTrip(snykRequest)
	}
	return snyk.Transport.RoundTrip(snykRequest)
}
