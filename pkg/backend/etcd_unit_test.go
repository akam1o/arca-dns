package backend

import (
	"encoding/json"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestEtcdBackendKeyHelpersNormalizeZoneNames(t *testing.T) {
	backend := &EtcdBackend{prefix: "/arca"}

	require.Equal(t, "/arca/zones/example.com.", backend.zoneKey("Example.COM"))
	require.Equal(t, "/arca/versions/example.com.", backend.versionKey("Example.COM"))
	require.Equal(t, "/arca/versions/", backend.versionPrefix())
	require.Equal(t, "/arca/history/example.com./v1", backend.historyKey("Example.COM", "v1"))
	require.Equal(t, "/arca/history/example.com./", backend.historyPrefixForZone("Example.COM"))
}

func TestEtcdBackendConvertEtcdEvent(t *testing.T) {
	backend := &EtcdBackend{prefix: "/arca"}
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: model.RecordTypeNS, TTL: 300, Value: "ns1.example.com."},
		},
	}
	zoneData, err := json.Marshal(zone)
	require.NoError(t, err)

	created := backend.convertEtcdEvent(&clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv: &mvccpb.KeyValue{
			Key:   []byte("/arca/zones/example.com."),
			Value: zoneData,
		},
	})
	require.NotNil(t, created)
	require.Equal(t, EventTypeCreated, created.Type)
	require.Equal(t, "example.com.", created.ZoneName)
	require.Equal(t, "v1", created.Version)
	require.Equal(t, zone.Records, created.Zone.Records)

	created.Zone.Records[0].Value = "mutated.example.com."
	require.Equal(t, "ns1.example.com.", zone.Records[0].Value, "event must contain a deep copy of records")

	updated := backend.convertEtcdEvent(&clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv: &mvccpb.KeyValue{
			Key:   []byte("/arca/zones/example.com."),
			Value: zoneData,
		},
		PrevKv: &mvccpb.KeyValue{Key: []byte("/arca/zones/example.com.")},
	})
	require.NotNil(t, updated)
	require.Equal(t, EventTypeUpdated, updated.Type)

	deleted := backend.convertEtcdEvent(&clientv3.Event{
		Type: clientv3.EventTypeDelete,
		Kv:   &mvccpb.KeyValue{Key: []byte("/arca/zones/example.com.")},
	})
	require.NotNil(t, deleted)
	require.Equal(t, EventTypeDeleted, deleted.Type)
	require.Equal(t, "example.com.", deleted.ZoneName)

	require.Nil(t, backend.convertEtcdEvent(&clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv:   &mvccpb.KeyValue{Key: []byte("/other/zones/example.com."), Value: zoneData},
	}))
	require.Nil(t, backend.convertEtcdEvent(&clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv:   &mvccpb.KeyValue{Key: []byte("/arca/zones/example.com."), Value: []byte("{")},
	}))
}

func TestEtcdBackendInfoAndCloseWithoutClient(t *testing.T) {
	backend := &EtcdBackend{}

	require.NoError(t, backend.Close())
	require.NoError(t, (*EtcdBackend)(nil).Close())

	info := backend.Info()
	require.Equal(t, "etcd", info.Type)
	require.Equal(t, "strong", info.Consistency)
	require.Contains(t, info.Capabilities, CapabilityZoneStore)
	require.Contains(t, info.Capabilities, CapabilityZoneCountStore)
	require.Contains(t, info.Capabilities, CapabilityWatchableStore)
	require.Contains(t, info.Capabilities, CapabilityConditionalDeleteStore)
}
