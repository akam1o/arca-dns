package promtext

import "strings"

// Label is a Prometheus text-format label name/value pair.
type Label struct {
	Name  string
	Value string
}

// FormatLabels renders a comma-separated Prometheus label set without braces.
func FormatLabels(labels ...Label) string {
	if len(labels) == 0 {
		return ""
	}

	var b strings.Builder
	for i, label := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(label.Name)
		b.WriteString("=\"")
		b.WriteString(EscapeLabelValue(label.Value))
		b.WriteByte('"')
	}
	return b.String()
}

// AppendLabels appends labels to an already formatted label set.
func AppendLabels(labelSet string, labels ...Label) string {
	extra := FormatLabels(labels...)
	if labelSet == "" {
		return extra
	}
	if extra == "" {
		return labelSet
	}
	return labelSet + "," + extra
}

// EscapeLabelValue escapes a Prometheus label value according to the text format.
func EscapeLabelValue(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
