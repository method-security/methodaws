package config

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/net/proxy"
)

type proxyContextKey struct{}

// ProxyConfig captures global proxy settings for AWS SDK HTTP traffic.
type ProxyConfig struct {
	HTTPProxy  string
	SOCKSProxy string
}

type AWSLoadOption = func(*awsconfig.LoadOptions) error

// SetProxyConfig stores proxy settings on the command context for paths that
// create their own AWS config later in execution.
func SetProxyConfig(ctx context.Context, proxyConfig ProxyConfig) context.Context {
	return context.WithValue(ctx, proxyContextKey{}, proxyConfig)
}

// ProxyConfigFromContext returns proxy settings from context, if present.
func ProxyConfigFromContext(ctx context.Context) ProxyConfig {
	if proxyConfig, ok := ctx.Value(proxyContextKey{}).(ProxyConfig); ok {
		return proxyConfig
	}
	return ProxyConfig{}
}

// AWSLoadOptionsForProxy returns AWS SDK config load options for proxy settings.
func AWSLoadOptionsForProxy(proxyConfig ProxyConfig) ([]AWSLoadOption, error) {
	client, err := HTTPClientForProxy(proxyConfig)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}
	loadOptions := []AWSLoadOption{awsconfig.WithHTTPClient(client)}
	if proxyConfig.SOCKSProxy != "" {
		transportOption, err := socksProxyTransportOption(proxyConfig.SOCKSProxy)
		if err != nil {
			return nil, err
		}
		loadOptions = append(loadOptions, awsconfig.WithServiceOptions(socksProxyServiceOption(transportOption)))
	}
	return loadOptions, nil
}

// AWSLoadOptionsFromContext returns AWS SDK config load options from context.
func AWSLoadOptionsFromContext(ctx context.Context) ([]AWSLoadOption, error) {
	return AWSLoadOptionsForProxy(ProxyConfigFromContext(ctx))
}

// HTTPClientForProxy creates an AWS buildable HTTP client configured for HTTP(S) or SOCKS5 proxies.
// If both proxy types are set, SOCKS5 takes precedence.
func HTTPClientForProxy(proxyConfig ProxyConfig) (*awshttp.BuildableClient, error) {
	if proxyConfig.HTTPProxy == "" && proxyConfig.SOCKSProxy == "" {
		return nil, nil
	}

	client := awshttp.NewBuildableClient()
	if proxyConfig.SOCKSProxy != "" {
		transportOption, err := socksProxyTransportOption(proxyConfig.SOCKSProxy)
		if err != nil {
			return nil, err
		}
		return client.WithTransportOptions(transportOption), nil
	}

	transportOption, err := httpProxyTransportOption(proxyConfig.HTTPProxy)
	if err != nil {
		return nil, err
	}
	return client.WithTransportOptions(transportOption), nil
}

func httpProxyTransportOption(rawProxyURL string) (func(*http.Transport), error) {
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP proxy URL: %w", err)
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid HTTP proxy scheme %q: expected http or https", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("invalid HTTP proxy URL: missing host")
	}

	return func(transport *http.Transport) {
		transport.Proxy = http.ProxyURL(proxyURL)
	}, nil
}

func socksProxyTransportOption(rawProxyURL string) (func(*http.Transport), error) {
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS proxy URL: %w", err)
	}
	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return nil, fmt.Errorf("invalid SOCKS proxy scheme %q: expected socks5 or socks5h", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("invalid SOCKS proxy URL: missing host")
	}

	dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS proxy dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS proxy dialer does not support context-aware dialing")
	}

	return func(transport *http.Transport) {
		transport.Proxy = noHTTPProxy
		transport.DialContext = contextDialer.DialContext
	}, nil
}

func noHTTPProxy(*http.Request) (*url.URL, error) {
	return nil, nil
}

func socksProxyServiceOption(transportOption func(*http.Transport)) func(string, any) {
	return func(_ string, options any) {
		optionsValue := reflect.ValueOf(options)
		if optionsValue.Kind() != reflect.Pointer || optionsValue.IsNil() {
			return
		}

		optionsElement := optionsValue.Elem()
		if optionsElement.Kind() != reflect.Struct {
			return
		}

		httpClientField := optionsElement.FieldByName("HTTPClient")
		if !httpClientField.IsValid() || !httpClientField.CanSet() || httpClientField.IsNil() {
			return
		}

		buildableClient, ok := httpClientField.Interface().(*awshttp.BuildableClient)
		if !ok {
			return
		}

		httpClientField.Set(reflect.ValueOf(buildableClient.WithTransportOptions(transportOption)))
	}
}
