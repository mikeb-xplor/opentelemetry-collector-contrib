// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

package apikeyauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/apikeyauthextension"

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension/auth"
	creds "google.golang.org/grpc/credentials"
)

var (
	errNoAuth              = errors.New("no auth provided")
	errInvalidCredentials  = errors.New("invalid credentials")
	errInvalidSchemePrefix = errors.New("invalid authorization scheme prefix")
	errInvalidFormat       = errors.New("invalid authorization format")
)

type bearerAuth struct {
	settings   *ApiKeySettings
	clientAuth *ClientAuthSettings
	matchFunc  func(apikey string) bool
}

func newClientAuthExtension(cfg *Config) auth.Client {
	ba := bearerAuth{
		clientAuth: cfg.ClientAuth,
	}
	return auth.NewClient(
		auth.WithClientRoundTripper(ba.roundTripper),
		auth.WithClientPerRPCCredentials(ba.perRPCCredentials),
	)
}

func newServerAuthExtension(cfg *Config) (auth.Server, error) {
	if cfg.Settings == nil || (cfg.Settings.File == "" && cfg.Settings.Inline == "") {
		return nil, errNoCredentialSource
	}

	ba := bearerAuth{
		settings: cfg.Settings,
	}
	return auth.NewServer(
		auth.WithServerStart(ba.serverStart),
		auth.WithServerAuthenticate(ba.authenticate),
	), nil
}

func (ba *bearerAuth) serverStart(_ context.Context, _ component.Host) error {
	var rs []io.Reader
	// var fileSize int64

	// Ensure that the inline content is read the last.
	// This way the inline content will override the content from file.
	if len(ba.settings.Inline) > 0 {
		rs = append(rs, strings.NewReader(ba.settings.Inline))
	} else {

		if ba.settings.File != "" {
			f, err := os.Open(ba.settings.File)

			// fileInfo, err := f.Stat()
			// if err != nil {
			// 	return fmt.Errorf("getting settings file size: %w", err)
			// }
			// fileSize = fileInfo.Size()

			if err != nil {
				return fmt.Errorf("open settings file: %w", err)
			}

			defer f.Close()

			rs = append(rs, f)
			rs = append(rs, strings.NewReader("\n"))
		}
	}

	mr := io.MultiReader(rs...)

	// var inlineLength int64 = int64(len(ba.settings.Inline))
	// var bufSize int64
	// if fileSize > inlineLength {
	// 	bufSize = fileSize
	// } else {
	// 	bufSize = inlineLength
	// }

	// bufSize = fileSize + inlineLength

	// buf := make([]byte, bufSize)
	// n, err := mr.Read(buf)

	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, mr)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	if err != nil && err != io.EOF {
		fmt.Println("Error reading:", err)
	}
	var keys = strings.Split(buf.String(), "\n")

	// htp, err := htpasswd.NewFromReader(mr, htpasswd.DefaultSystems, nil)
	// if err != nil {
	// 	return fmt.Errorf("read settings content: %w", err)
	// }

	//ba.matchFunc = htp.Match

	ba.matchFunc = func(apikey string) bool {

		// for i := 0 i < len(keys); i++ {
		// 	fmt.Println(keys[i])
		// }
		return checkKey(apikey, keys)
	}

	return nil
}

func checkKey(keyToFind string, keys []string) bool {

	// fmt.Printf("find match for: %s", keyToFind)
	// fmt.Printf("keys to check: %d", len(keys))

	for _, k := range keys {
		// fmt.Printf("%s == %s\n\n", keyToFind, k)
		if k == keyToFind {
			// fmt.Println("found!!!")
			return true
		}
	}

	// fmt.Printf("failed to match: %s", keyToFind)

	return false

}

func (ba *bearerAuth) authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	auth := getAuthHeader(headers)
	if auth == "" {
		return ctx, errNoAuth
	}

	authData, err := parseBearerAuth(auth)
	if err != nil {
		return ctx, err
	}

	if !ba.matchFunc(authData.apikey) {
		return ctx, errInvalidCredentials
	}

	cl := client.FromContext(ctx)
	cl.Auth = authData
	return client.NewContext(ctx, cl), nil
}

func getAuthHeader(h map[string][]string) string {
	const (
		canonicalHeaderKey = "Authorization"
		metadataKey        = "authorization"
	)

	authHeaders, ok := h[canonicalHeaderKey]

	if !ok {
		authHeaders, ok = h[metadataKey]
	}

	if !ok {
		for k, v := range h {
			if strings.EqualFold(k, metadataKey) {
				authHeaders = v
				break
			}
		}
	}

	if len(authHeaders) == 0 {
		return ""
	}

	return authHeaders[0]
}

// See: https://github.com/golang/go/blob/1a8b4e05b1ff7a52c6d40fad73bcad612168d094/src/net/http/request.go#L950
func parseBearerAuth(auth string) (*authData, error) {
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return nil, errInvalidSchemePrefix
	}

	encoded := auth[len(prefix):]
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errInvalidFormat
	}
	decoded := string(decodedBytes)

	return &authData{
		apikey: decoded,
		raw:    encoded,
	}, nil
}

var _ client.AuthData = (*authData)(nil)

type authData struct {
	apikey string
	raw    string
}

func (a *authData) GetAttribute(name string) any {
	switch name {
	// case "apikey":
	// 	return a.apikey
	case "raw":
		return a.raw
	default:
		return nil
	}
}

func (*authData) GetAttributeNames() []string {
	return []string{"raw"}
}

// perRPCAuth is a gRPC credentials.PerRPCCredentials implementation that returns an 'authorization' header.
type perRPCAuth struct {
	metadata map[string]string
}

// GetRequestMetadata returns the request metadata to be used with the RPC.
func (p *perRPCAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return p.metadata, nil
}

// RequireTransportSecurity always returns true for this implementation.
func (p *perRPCAuth) RequireTransportSecurity() bool {
	return true
}

type bearerAuthRoundTripper struct {
	base     http.RoundTripper
	authData *ClientAuthSettings
}

func (b *bearerAuthRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	newRequest := request.Clone(request.Context())
	newRequest.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte(b.authData.ApiKey)))

	return b.base.RoundTrip(newRequest)
}

func (ba *bearerAuth) roundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	return &bearerAuthRoundTripper{
		base:     base,
		authData: ba.clientAuth,
	}, nil
}

func (ba *bearerAuth) perRPCCredentials() (creds.PerRPCCredentials, error) {

	encoded := base64.StdEncoding.EncodeToString([]byte(string(ba.clientAuth.ApiKey)))
	return &perRPCAuth{
		metadata: map[string]string{
			"authorization": fmt.Sprintf("Bearer %s", encoded),
		},
	}, nil
}
