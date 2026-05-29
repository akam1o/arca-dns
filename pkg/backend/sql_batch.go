package backend

import (
	"fmt"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
)

const sqlBatchLoadZoneLimit = 500

func sqlBatchEnd(start, total int) int {
	end := start + sqlBatchLoadZoneLimit
	if end > total {
		return total
	}
	return end
}

func sqlQuestionPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", count), ",")
}

func sqlNumberedPlaceholders(start, count int) string {
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(placeholders, ",")
}

func sqlZoneNameArgs(zones []*model.Zone, start, end int) []interface{} {
	args := make([]interface{}, 0, end-start)
	for _, zone := range zones[start:end] {
		args = append(args, zone.Name)
	}
	return args
}

func assignZoneRecords(zones []*model.Zone, recordsByZone map[string][]model.Record) {
	for _, zone := range zones {
		if records, ok := recordsByZone[zone.Name]; ok {
			zone.Records = records
			continue
		}
		zone.Records = []model.Record{}
	}
}
