package promtext

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatLabelsEscapesPrometheusLabelValues(t *testing.T) {
	got := FormatLabels(
		Label{Name: "path", Value: "/zones/with\"quote"},
		Label{Name: "status", Value: "bad\nstatus\\tail"},
	)

	require.Equal(t, `path="/zones/with\"quote",status="bad\nstatus\\tail"`, got)
}

func TestAppendLabels(t *testing.T) {
	require.Equal(t, `le="+Inf"`, AppendLabels("", Label{Name: "le", Value: "+Inf"}))
	require.Equal(t, `method="GET",le="1"`, AppendLabels(`method="GET"`, Label{Name: "le", Value: "1"}))
}
