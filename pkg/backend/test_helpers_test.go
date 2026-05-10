package backend

import "github.com/akam1o/arca-dns/pkg/model"

func testApexNSRecord(zoneName string) model.Record {
	return model.Record{
		Name:  "@",
		Type:  model.RecordTypeNS,
		TTL:   300,
		Value: "ns1." + model.NormalizeZoneName(zoneName),
	}
}

func testZoneRecords(zoneName string, records ...model.Record) []model.Record {
	return append([]model.Record{testApexNSRecord(zoneName)}, records...)
}
