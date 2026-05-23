package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type openAPIDocument struct {
	Paths      map[string]openAPIPathItem `yaml:"paths"`
	Components struct {
		Schemas map[string]openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
}

type openAPIPathItem struct {
	Get openAPIOperation `yaml:"get"`
}

type openAPIOperation struct {
	Parameters []openAPIParameter `yaml:"parameters"`
	Security   []map[string]any   `yaml:"security"`
}

type openAPIParameter struct {
	Name   string        `yaml:"name"`
	In     string        `yaml:"in"`
	Schema openAPISchema `yaml:"schema"`
}

type openAPISchema struct {
	Type        string                   `yaml:"type"`
	Enum        []string                 `yaml:"enum"`
	Default     string                   `yaml:"default"`
	Description string                   `yaml:"description"`
	Properties  map[string]openAPISchema `yaml:"properties"`
}

func loadOpenAPIContract(t *testing.T) openAPIDocument {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	require.NoError(t, err)

	var doc openAPIDocument
	require.NoError(t, yaml.Unmarshal(data, &doc))
	return doc
}

func findOpenAPIQueryParameter(params []openAPIParameter, name string) (openAPIParameter, bool) {
	for _, param := range params {
		if param.In == "query" && param.Name == name {
			return param, true
		}
	}
	return openAPIParameter{}, false
}

func TestOpenAPIListZonesFieldsMatchHandler(t *testing.T) {
	doc := loadOpenAPIContract(t)
	listZones := doc.Paths["/zones"].Get

	fieldsParam, ok := findOpenAPIQueryParameter(listZones.Parameters, "fields")
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"full", "summary"}, fieldsParam.Schema.Enum)
	assert.Equal(t, "full", fieldsParam.Schema.Default)

	_, ok = findOpenAPIQueryParameter(listZones.Parameters, "filter")
	assert.False(t, ok, "OpenAPI must not document unsupported list filters")

	_, _, server := setupTest(t)
	defer server.Close()

	for _, fields := range fieldsParam.Schema.Enum {
		resp, err := http.Get(server.URL + "/api/v1/zones?fields=" + fields)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "documented fields value %q should be accepted", fields)
	}
}

func TestOpenAPIPaginationDocumentsNextOffset(t *testing.T) {
	doc := loadOpenAPIContract(t)
	pagination := doc.Components.Schemas["Pagination"]

	nextOffset, ok := pagination.Properties["next_offset"]
	require.True(t, ok)
	assert.Equal(t, "integer", nextOffset.Type)
	assert.NotEmpty(t, nextOffset.Description)
}

func TestOpenAPIMetricsDocumentsOptionalBearerAuth(t *testing.T) {
	doc := loadOpenAPIContract(t)
	metrics := doc.Paths["/metrics"].Get

	require.Len(t, metrics.Security, 2)
	assert.Contains(t, metrics.Security[0], "ObservabilityBearerAuth")
	assert.Empty(t, metrics.Security[1])
}
