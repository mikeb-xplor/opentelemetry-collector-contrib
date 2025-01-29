// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

package apikeyauthextension

import (
	"path/filepath"
	"testing"

	"github.com/mikeb-xplor/opentelemetry-collector-contrib/extension/apikeyauthextension/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id          component.ID
		expected    component.Config
		expectedErr bool
	}{
		{
			id:          component.NewID(metadata.Type),
			expectedErr: true,
		},
		{
			id: component.NewIDWithName(metadata.Type, "server"),
			expected: &Config{
				Settings: &ApiKeySettings{
					Inline: "key1\nkey2\n",
					File:   "./testdata/.settings",
				},
			},
		},
		{
			id: component.NewIDWithName(metadata.Type, "client"),
			expected: &Config{
				ClientAuth: &ClientAuthSettings{
					ApiKey: "key",
				},
			},
		},
		{
			id:          component.NewIDWithName(metadata.Type, "both"),
			expectedErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			var path = filepath.Join("testdata", "config.yaml")
			cm, err := confmaptest.LoadConf(path)
			require.NoError(t, err)
			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()
			sub, err := cm.Sub(tt.id.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(cfg))
			if tt.expectedErr {
				assert.Error(t, component.ValidateConfig(cfg))
				return
			}
			assert.NoError(t, component.ValidateConfig(cfg))
			assert.Equal(t, tt.expected, cfg)
		})
	}
}
