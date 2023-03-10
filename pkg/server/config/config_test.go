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
	expectedBadSpiffeId, _ := spiffeid.FromString("")

	expected := AuthenticatingProxy{AllowedSpiffeIds: []spiffeid.ID{expectedBadSpiffeId, expectedBadSpiffeId}}

	require.Error(t, err, "Failed to catch SPIFFE error")
	require.Equal(t, &expected, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}

func TestSpiffeIdBadConfigPlus(t *testing.T) {
	expectedBadSpiffeId, _ := spiffeid.FromString("")
	expectedAp := AuthenticatingProxy{
		Hostname:         "proxy.com",
		AllowedSpiffeIds: []spiffeid.ID{expectedBadSpiffeId, expectedBadSpiffeId},
	}

	conf, err := Load(badSpiffeConfigPlusYaml)

	require.Error(t, err, "Failed to catch SPIFFE error")
	require.Equal(t, &expectedAp, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}

func TestSpiffeIdMixedConfig(t *testing.T) {
	expectedBadSpiffeId, _ := spiffeid.FromString("")
	expectedAp := AuthenticatingProxy{
		AllowedSpiffeIds: []spiffeid.ID{spiffeid.RequireFromString("spiffe://proxy.com"), expectedBadSpiffeId},
	}

	conf, err := Load(mixedSpiffeConfigYaml)

	require.Error(t, err, "Failed to catch SPIFFE errors")
	require.ErrorContains(t, err, "failed to parse: [1]", "Failed to identify the appropriately failed SPIFFE ID")
	require.Equal(t, &expectedAp, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}

func TestSpiffeIdBadTypeConfig(t *testing.T) {

	conf, err := Load(badConfigTypeYaml)

	expectedConf := Config{AuthenticatingProxy: nil}

	require.Error(t, err, "Failed to catch YAML errors")
	require.NotContains(t, err.Error(), "spiffe", "Incorrectly reported error as SPIFFE error")
	require.Equal(t, expectedConf.AuthenticatingProxy, conf.AuthenticatingProxy, "Authenticated Proxies do not match")
}
