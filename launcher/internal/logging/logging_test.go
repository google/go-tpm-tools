package logging

import (
	"reflect"
	"testing"
)

func TestAddArgs(t *testing.T) {
	testcases := []struct {
		name     string
		args     []any
		expected payload
	}{
		{
			name: "regular payload",
			args: []any{"key1", 1, "key2", "two", "key3", false},
			expected: payload{
				"key1": 1,
				"key2": "two",
				"key3": false,
			},
		},
		{
			name: "missing value at end",
			args: []any{"key1", 1, "key2", "two", "key3"},
			expected: payload{
				"key1": 1,
				"key2": "two",
				"key3": "",
			},
		},
		{
			name:     "empty args",
			args:     []any{},
			expected: payload{},
		},
		{
			name: "incompatible key omitted",
			args: []any{"key1", 1, 2, "two", "key3", false},
			expected: payload{
				"key1": 1,
				"key3": false,
			},
		},
		{
			name: "single arg, valid key",
			args: []any{"key1"},
			expected: payload{
				"key1": "",
			},
		},
		{
			name:     "single arg, not valid key",
			args:     []any{true},
			expected: payload{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pl := payload{}
			addArgs(pl, tc.args)

			if !reflect.DeepEqual(pl, tc.expected) {
				t.Errorf("addArgs did not produce expected payload: got %v, want %v", pl, tc.expected)
			}
		})
	}
}
