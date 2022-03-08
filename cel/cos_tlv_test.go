package cel

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

func TestCosEventlog(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	testEvents := []struct {
		cosNestedEventType CosType
		pcr                int
		eventPayload       []byte
	}{
		{ImageRefType, test.DebugPCR, []byte("docker.io/bazel/experimental/test:latest")},
		{ImageDigestType, test.DebugPCR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{RestartPolicyType, test.DebugPCR, []byte(pb.RestartPolicy_Never.String())},
		{ImageIDType, test.DebugPCR, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{EnvVarType, test.DebugPCR, []byte("foo=bar")},
		{EnvVarType, test.DebugPCR, []byte("override-env-1=foo")},
		{EnvVarType, test.DebugPCR, []byte("baz=foo=bar")},
		{EnvVarType, test.DebugPCR, []byte("empty=")},
		{EnvVarType, test.DebugPCR, []byte("override-env-2=foo")},
		{OverrideEnvType, test.DebugPCR, []byte("override-env-1=foo")},
		{OverrideEnvType, test.DebugPCR, []byte("override-env-2=foo")},
		{ArgType, test.DebugPCR, []byte("--x")},
		{ArgType, test.DebugPCR, []byte("--override-arg-1")},
		{ArgType, test.DebugPCR, []byte("--override-arg-2")},
		{OverrideArgType, test.DebugPCR, []byte("--override-arg1")},
		{OverrideArgType, test.DebugPCR, []byte("--override-arg2")},
	}

	for _, testEvent := range testEvents {
		cos := CosTlv{testEvent.cosNestedEventType, testEvent.eventPayload}
		if err := cel.AppendEvent(tpm, testEvent.pcr, measuredHashes, cos); err != nil {
			t.Fatal(err.Error())
		}
	}

	var buf bytes.Buffer
	if err := cel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if len(decodedcel.Records) != len(testEvents) {
		t.Errorf("should have %d records, but got %d", len(testEvents), len(decodedcel.Records))
	}

	for i, testEvent := range testEvents {
		extractedCos, err := decodedcel.Records[i].Content.ParseToCosTlv()
		if err != nil {
			t.Fatal(err)
		}

		want := CosTlv{testEvent.cosNestedEventType, testEvent.eventPayload}
		if !cmp.Equal(extractedCos, want) {
			t.Errorf("decoded COS TLV got %+v, want %+v", extractedCos, want)
		}
	}
}

func TestParseEnvVar(t *testing.T) {
	tests := []struct {
		testName             string
		envVar               string
		envName              string
		envValue             string
		expectedErrSubstring string
	}{
		{"normal case 1", "foo=bar", "foo", "bar", ""},
		{"normal case 2", "FOO=1", "FOO", "1", ""},
		{"normal case 3", "SESSION_MANAGER=\"`\\local/:@?%/tmp/.u/1,unix/.com:/tmp/.u/5\"", "SESSION_MANAGER", "\"`\\local/:@?%/tmp/.u/1,unix/.com:/tmp/.u/5\"", ""},
		{"no =", "foo", "", "", "malformed env var, doesn't contain '='"},
		{"empty", "", "", "", "malformed env var, doesn't contain '='"},
		{"empty value", "foo=", "foo", "", ""},
		{"multiple =", "foo=bar=baz=", "foo", "bar=baz=", ""},
		{"bad name", "3foo=bar=baz=", "", "", "env name must start with an alpha character or '_'"},
		{"bad name quote", "foo\"=bar=baz=", "", "", "env name must start with an alpha character or '_'"},
		{"empty name", "=bar=baz=", "", "", "env name must start with an alpha character or '_'"},
		{"non utf-8 value", string([]byte{'f', '=', 0xC0, 2, 2, '='}), "", "", "malformed env value, contains non-utf8 character"},
		{"non utf-8 name", string([]byte{'a', 0xC0, 2, 2, '='}), "", "", "malformed env name, contains non-utf8 character"},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			n, v, err := ParseEnvVar(test.envVar)

			if n != test.envName {
				t.Errorf("envName mismatch, want [%s], got [%s]", test.envName, n)
			}
			if v != test.envValue {
				t.Errorf("envValue mismatch, want [%s], got [%s]", test.envValue, v)
			}
			if test.expectedErrSubstring == "" {
				if err != nil {
					t.Errorf("expected no error, but got [%s]", err)
				} else {
					formattedEnvVar, err := FormatEnvVar(test.envName, test.envValue)
					if err != nil {
						t.Errorf("expected no error, but got [%s]", err)
					} else if formattedEnvVar != test.envVar {
						t.Errorf("formattedEnvVar mismatch, want [%s], got [%s]", test.envVar, formattedEnvVar)
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected error substring [%s], but got no error", test.expectedErrSubstring)
				} else if !strings.Contains(err.Error(), test.expectedErrSubstring) {
					t.Errorf("expected error substring [%s], but got [%v]", test.expectedErrSubstring, err)
				}
			}
		})
	}
}
