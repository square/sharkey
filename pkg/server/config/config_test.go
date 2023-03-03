package config

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

const (
	goodSpiffeConfigYaml    = "testdata/goodSpiffeConfig.yaml"
	badSpiffeConfigYaml     = "testdata/badSpiffeConfig.yaml"
	mixedSpiffeConfigYaml   = "testdata/mixedSpiffeConfig.yaml"
	badSpiffeConfigPlusYaml = "testdata/badSpiffeConfigPlus.yaml"
	badConfigTypeYaml       = "testdata/badConfigType.yaml"
)

func TestSpiffeIdGoodConfigFill(t *testing.T) {
	conf, err := Load(goodSpiffeConfigYaml)

	goodAp := AuthenticatingProxy{
		AllowedSpiffeIds: []spiffeid.ID{
			spiffeid.RequireFromString("spiffe://proxy.com"),
			spiffeid.RequireFromString("spiffe://proxy2.com"),
		},
	}
	goodConf := Config{AuthenticatingProxy: &goodAp}
	require.NoError(t, err, "Failed to load configuration file")
	require.Equal(t, goodConf, conf, "Authenticated Proxies do not match")
}

func TestSpiffeIdBadConfigFill(t *testing.T) {
	conf, err := Load(badSpiffeConfigYaml)

	expected := AuthenticatingProxy{}

	require.Error(t, err, "Failed to catch SPIFFE error")
	require.ErrorContains(t, err, "failed to parse spiffe ids at indices [0 1]:")
	require.Equal(t, &expected, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}

func TestSpiffeIdBadConfigPlus(t *testing.T) {
	expectedAp := AuthenticatingProxy{Hostname: "proxy.com"}

	conf, err := Load(badSpiffeConfigPlusYaml)

	require.Error(t, err, "Failed to catch SPIFFE error")
	require.ErrorContains(t, err, "failed to parse spiffe ids at indices [0 1]:")
	require.Equal(t, &expectedAp, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}

func TestSpiffeIdMixedConfig(t *testing.T) {
	expectedAp := AuthenticatingProxy{
		AllowedSpiffeIds: []spiffeid.ID{spiffeid.RequireFromString("spiffe://proxy.com")},
	}

	conf, err := Load(mixedSpiffeConfigYaml)

	require.Error(t, err, "Failed to catch SPIFFE errors")
	require.ErrorContains(t, err, "failed to parse spiffe ids at indices [1]:")
	require.Equal(t, &expectedAp, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}
