//go:build integration

package workloadservice

var keyHandleSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"handle": map[string]interface{}{"type": "string"},
	},
	"required": []interface{}{"handle"},
	"additionalProperties": false,
}

var algorithmSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"type": map[string]interface{}{"type": "string", "enum": []interface{}{"kem"}},
		"params": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"kem_id": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"kem_id"},
			"additionalProperties": false,
		},
	},
	"required": []interface{}{"type", "params"},
	"additionalProperties": false,
}

var pubKeySchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"algorithm": algorithmSchema,
		"public_key": map[string]interface{}{"type": "string"},
	},
	"required": []interface{}{"algorithm", "public_key"},
	"additionalProperties": false,
}

var keyInfoSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"key_handle": keyHandleSchema,
		"pub_key": pubKeySchema,
		"key_protection_mechanism": map[string]interface{}{"type": "string"},
		"expiration_time": map[string]interface{}{"type": "integer"},
	},
	"required": []interface{}{"key_handle", "pub_key", "key_protection_mechanism", "expiration_time"},
	"additionalProperties": false,
}

var getCapabilitiesSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"supported_algorithms": map[string]interface{}{
			"type": "array",
			"items": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"algorithm": algorithmSchema,
				},
				"required": []interface{}{"algorithm"},
				"additionalProperties": false,
			},
		},
	},
	"required": []interface{}{"supported_algorithms"},
	"additionalProperties": false,
}

var decapsResponseSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"shared_secret": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"algorithm": map[string]interface{}{"type": "string"},
				"secret": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"algorithm", "secret"},
			"additionalProperties": false,
		},
	},
	"required": []interface{}{"shared_secret"},
	"additionalProperties": false,
}

var enumerateKeysSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"key_infos": map[string]interface{}{
			"type": "array",
			"items": keyInfoSchema,
		},
	},
	"required": []interface{}{"key_infos"},
	"additionalProperties": false,
}
