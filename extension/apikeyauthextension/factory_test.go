// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

package apikeyauthextension // import "github.com/mikeb-xplor/opentelemetry-collector-contrib/extension/apikeyauthextension"

import (
	"context"
	"testing"

	"github.com/mikeb-xplor/opentelemetry-collector-contrib/extension/apikeyauthextension/internal/metadata"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestCreateDefaultConfig(t *testing.T) {
	expected := &Config{}
	actual := createDefaultConfig()
	assert.Equal(t, expected, createDefaultConfig())
	assert.NoError(t, componenttest.CheckConfigStruct(actual))
}

func TestCreateExtension_ValidConfig(t *testing.T) {
	cfg := &Config{
		Settings: &ApiKeySettings{
			Inline: "password",
		},
	}

	ext, err := createExtension(context.Background(), extensiontest.NewNopSettings(), cfg)
	assert.NoError(t, err)
	assert.NotNil(t, ext)
}

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	assert.NotNil(t, f)
	assert.Equal(t, f.Type(), metadata.Type)
}
