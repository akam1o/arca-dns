package backend

import "github.com/akam1o/arca-dns/pkg/model"

func cloneDNSSECConfig(config *model.DNSSECConfig) *model.DNSSECConfig {
	if config == nil {
		return nil
	}

	cloned := *config
	if config.SignatureExpiration != nil {
		expiration := *config.SignatureExpiration
		cloned.SignatureExpiration = &expiration
	}
	return &cloned
}

func dnssecColumnValues(config *model.DNSSECConfig) (enabled bool, algorithm, kskKeyTag, zskKeyTag interface{}, nsec3Enabled bool, nsec3Iterations, nsec3Salt, signatureExpiration interface{}) {
	if config == nil || !config.Enabled {
		return false, nil, nil, nil, false, nil, nil, nil
	}

	enabled = true
	algorithm = config.Algorithm
	kskKeyTag = config.KSKKeyTag
	zskKeyTag = config.ZSKKeyTag
	nsec3Enabled = config.NSEC3Enabled
	nsec3Iterations = config.NSEC3Iterations
	nsec3Salt = config.NSEC3Salt
	if config.SignatureExpiration != nil && !config.SignatureExpiration.IsZero() {
		signatureExpiration = config.SignatureExpiration
	}

	return enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration
}
