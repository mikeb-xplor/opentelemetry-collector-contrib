// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

package apikeyauthextension // import "github.com/mikeb-xplor/opentelemetry-collector-contrib/extension/apikeyauthextension"

import (
	"errors"

	"go.opentelemetry.io/collector/config/configopaque"
)

var (
	errNoCredentialSource     = errors.New("no credential source provided")
	errMultipleAuthenticators = errors.New("only server or client settings and be provided, not both")
)

type ApiKeySettings struct {
	// Path to the api keys file.
	File string `mapstructure:"file"`
	// Inline contents of the settings file.
	Inline string `mapstructure:"inline"`
}

type ClientAuthSettings struct {
	// ApiKey holds the password to use for client authentication.
	ApiKey configopaque.String `mapstructure:"apikey"`
}
type Config struct {
	// Settings settings.
	Settings *ApiKeySettings `mapstructure:"settings,omitempty"`

	// ClientAuth settings
	ClientAuth *ClientAuthSettings `mapstructure:"client_auth,omitempty"`
}

func (cfg *Config) Validate() error {
	serverCondition := cfg.Settings != nil
	clientCondition := cfg.ClientAuth != nil

	if serverCondition && clientCondition {
		return errMultipleAuthenticators
	}

	if !serverCondition && !clientCondition {
		return errNoCredentialSource
	}

	return nil
}
