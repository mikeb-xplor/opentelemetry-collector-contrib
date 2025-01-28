// Derived from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/basicauthextension
// Copyright The OpenTelemetry Authors
// Copyright Xplor Technologies
// SPDX-License-Identifier: Apache-2.0

//go:generate mdatagen metadata.yaml

// Package apikeyauthextension implements an extension offering Bearer token authentication over HTTP with a simple Base64 encoded key
package apikeyauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/apikeyauthextension"
