// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

package apikeyauthextension

import (
	"context"

	"github.com/mikeb-xplor/opentelemetry-collector-contrib/extension/apikeyauthextension/internal/metadata"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

// NewFactory creates a factory for the static bearer token Authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createExtension(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
	// check if config is a server auth(settings should be set)
	if cfg.(*Config).Settings != nil {
		return newServerAuthExtension(cfg.(*Config))
	}
	return newClientAuthExtension(cfg.(*Config)), nil
}
