package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"

	"github.com/snyk-labs/snyk-sso-membership/pkg/config"
)

const (
	RequestTimeout = 30
	MaxRetries     = 3
)

type SnykClient interface {
	Get(uriPath string) ([]byte, error)
	Post(uriPath string, body io.Reader) ([]byte, error)
	Patch(uriPath string, body io.Reader) ([]byte, error)
	Delete(uriPath string) ([]byte, error)
}

type SnykClientImpl struct {
	baseURI             string
	authorizationHeader string
	httpClient          *http.Client
	logger              *zerolog.Logger
}

type retryableLogger struct {
	logger *zerolog.Logger
}

func (rl *retryableLogger) Printf(format string, v ...any) {
	// set to debug level for explicit logging
	rl.logger.Debug().Msgf(format, v...)
}

func New(cfg *config.Config) SnykClient {
	c := &SnykClientImpl{}
	c.baseURI = cfg.BaseURI
	c.authorizationHeader = cfg.AuthorizationHeader
	output := zerolog.ConsoleWriter{Out: os.Stderr}
	logger := zerolog.New(output).With().Timestamp().Logger()
	c.logger = &logger
	transport := NewSnykAPITransport(cfg.AuthorizationHeader, cfg.Version, cfg.SkipVerifyTLS)
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient.Transport = transport
	retryClient.RetryMax = MaxRetries
	retryClient.Logger = &retryableLogger{logger: &logger}
	c.httpClient = retryClient.StandardClient()

	return c
}

func (c *SnykClientImpl) Request(method, path string, body io.Reader) (*http.Response, error) {
	base, err := url.Parse(c.baseURI)
	if err != nil {
		c.logger.Error().Err(err).Msg(fmt.Sprintf("invalid base url: %s", c.baseURI))
	}
	requestPath, err := url.Parse(path)
	if err != nil {
		c.logger.Error().Err(err).Msg(fmt.Sprintf("failed to parse request path: %s", path))
	}
	requestURL := base.ResolveReference(requestPath)

	urlValue := requestURL.String()
	req, err := http.NewRequestWithContext(context.Background(), method, urlValue, body)
	if err != nil {
		c.logger.Error().Err(err).Msg(fmt.Sprintf("failed to create request: %s", err.Error()))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error().Err(err).Msg(fmt.Sprintf("failed to create request url: %s, %s", urlValue, err.Error()))
		return nil, err
	}
	if resp != nil && resp.StatusCode >= http.StatusBadRequest {
		if resp.ContentLength > 0 {
			if body, err := io.ReadAll(resp.Body); err == nil {
				c.logger.Debug().Msg(fmt.Sprintf("%d response body: %s", resp.StatusCode, string(body)))
			}
		}
		return resp, fmt.Errorf("failed to %s %s: %d", method, urlValue, resp.StatusCode)
	}
	c.logger.Debug().Msg(fmt.Sprintf("%d response: %s: %s", resp.StatusCode, method, urlValue))
	return resp, err
}

func (c *SnykClientImpl) Get(path string) ([]byte, error) {
	resp, respErr := c.Request("GET", path, nil)
	if resp == nil && respErr != nil {
		return nil, respErr
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		c.logger.Debug().Msg(string(body))
		// return response error if any
		return body, respErr
	}

	return nil, respErr
}

func (c *SnykClientImpl) Post(path string, body io.Reader) ([]byte, error) {
	resp, err := c.Request("POST", path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		c.logger.Debug().Msg(string(body))
		return body, nil
	}

	return nil, err
}

func (c *SnykClientImpl) Patch(path string, body io.Reader) ([]byte, error) {
	resp, err := c.Request("PATCH", path, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 204 {
		return nil, nil
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		c.logger.Debug().Msg(string(body))
		return body, nil
	}

	return nil, err
}

func (c *SnykClientImpl) Delete(path string) ([]byte, error) {
	resp, err := c.Request("DELETE", path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 204 {
		return nil, nil
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		c.logger.Debug().Msg(string(body))
		return body, nil
	}

	return nil, err
}
