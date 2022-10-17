package server

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	cosImageRef    string = "docker.io/bazel/experimental/test:latest"
	cosImageDigest string = "sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483"
	cosImageID     string = "sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B"
	argX           string = "--x"
	overrideArg1   string = "--override-arg1"
	overrideArg2   string = "--override-arg2"
)

var (
	defaultSemVer attestpb.SemanticVersion = attestpb.SemanticVersion{Major: 0, Minor: 1, Patch: 0}
)

func TestParseAttestedCosStatev0_1_0(t *testing.T) {
	// This test uses the CosEventPCR (PCR13), which is not resettable.
	test.SkipForRealTPM(t)
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	coscel := &cel.CEL{}

	measureLauncherVersionEvent(t, coscel, tpm, &defaultSemVer)
	measureTestLauncherv0Events(t, coscel, tpm)

	var buf bytes.Buffer
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	want := attestpb.AttestedCosState{
		LauncherVersion: &defaultSemVer,
		Container: &attestpb.ContainerState{
			ImageReference:    cosImageRef,
			ImageDigest:       cosImageDigest,
			RestartPolicy:     attestpb.RestartPolicy_OnFailure,
			ImageId:           cosImageID,
			EnvVars:           expectedCosEnvVars(),
			Args:              []string{argX, overrideArg1, overrideArg2},
			OverriddenEnvVars: expectedOverriddenCosEnvVars(),
			OverriddenArgs:    []string{overrideArg1, overrideArg2},
		},
	}
	banks, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		if msState, err := parseCanonicalEventLog(buf.Bytes(), bank); err != nil {
			t.Errorf("expecting no error from parseCanonicalEventLog(), but get %v", err)
		} else {
			if diff := cmp.Diff(msState.Cos, &want, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference:\n%v", diff)
			}
		}
	}
}

func TestParseAttestedCosStateNoVersion(t *testing.T) {
	test.SkipForRealTPM(t)
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	coscel := &cel.CEL{}
	measureTestLauncherv0Events(t, coscel, tpm)

	var buf bytes.Buffer
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	want := attestpb.AttestedCosState{
		LauncherVersion: &defaultSemVer,
		Container: &attestpb.ContainerState{
			ImageReference:    cosImageRef,
			ImageDigest:       cosImageDigest,
			RestartPolicy:     attestpb.RestartPolicy_OnFailure,
			ImageId:           cosImageID,
			EnvVars:           expectedCosEnvVars(),
			Args:              []string{argX, overrideArg1, overrideArg2},
			OverriddenEnvVars: expectedOverriddenCosEnvVars(),
			OverriddenArgs:    []string{overrideArg1, overrideArg2},
		},
	}
	banks, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		if msState, err := parseCanonicalEventLog(buf.Bytes(), bank); err != nil {
			t.Errorf("expecting no error from parseCanonicalEventLog(), but get %v", err)
		} else {
			if diff := cmp.Diff(msState.Cos, &want, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference:\n%v", diff)
			}
		}
	}
}

func TestParseAttestedCosStateBadVersion(t *testing.T) {
	test.SkipForRealTPM(t)
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	coscel := &cel.CEL{}
	// Wrong size event content; should be of size 12.
	cosTlv := cel.CosTlv{EventType: cel.LauncherVersionType, EventContent: []byte{0, 1, 2, 3}}
	if err := coscel.AppendEvent(tpm, cel.CosEventPCR, getImplementedHashes(t, tpm), cosTlv); err != nil {
		t.Fatalf("failed to append event to COS CEL: %v", err)
	}

	var buf bytes.Buffer
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		if _, err := parseCanonicalEventLog(buf.Bytes(), bank); err == nil {
			t.Error("expected wrong size error from parseCanonicalEventLog()")
		}
	}
}

func measureLauncherVersionEvent(t *testing.T, coscel *cel.CEL, tpm io.ReadWriteCloser, semver *attestpb.SemanticVersion) {
	cosTlv := cel.CosTlv{EventType: cel.LauncherVersionType, EventContent: cel.FormatSemVer(semver)}
	if err := coscel.AppendEvent(tpm, cel.CosEventPCR, getImplementedHashes(t, tpm), cosTlv); err != nil {
		t.Fatalf("failed to append event to COS CEL: %v", err)
	}
}

func measureTestLauncherv0Events(t *testing.T, coscel *cel.CEL, tpm io.ReadWriteCloser) {
	// Measurements should generally match the order and types in launcher major version 0.
	// https://github.com/google/go-tpm-tools/blob/87b2a5e7126c46e6120b7737ed58125447e9aef9/launcher/container_runner.go#L275-L330.
	testEvents := []struct {
		eventType    cel.CosType
		eventContent []byte
	}{
		{cel.ImageRefType, []byte(cosImageRef)},
		{cel.ImageDigestType, []byte(cosImageDigest)},
		{cel.RestartPolicyType, []byte(attestpb.RestartPolicy_OnFailure.String())},
		{cel.ImageIDType, []byte(cosImageID)},
		{cel.ArgType, []byte(argX)},
		{cel.ArgType, []byte(overrideArg1)},
		{cel.ArgType, []byte(overrideArg2)},
		{cel.EnvVarType, []byte("foo=bar")},
		{cel.EnvVarType, []byte("override_env_1=foo")},
		{cel.EnvVarType, []byte("baz=foo=bar")},
		{cel.EnvVarType, []byte("empty=")},
		{cel.EnvVarType, []byte("override_env_2=foo")},
		{cel.OverrideEnvType, []byte("override_env_1=foo")},
		{cel.OverrideEnvType, []byte("override_env_2=foo")},
		{cel.OverrideArgType, []byte("--override-arg1")},
		{cel.OverrideArgType, []byte("--override-arg2")},
		{cel.LaunchSeparatorType, nil},
	}
	for _, testEvent := range testEvents {
		cosTlv := cel.CosTlv{EventType: testEvent.eventType, EventContent: testEvent.eventContent}
		if err := coscel.AppendEvent(tpm, cel.CosEventPCR, getImplementedHashes(t, tpm), cosTlv); err != nil {
			t.Fatalf("failed to append event to COS CEL: %v", err)
		}
	}
}

func expectedCosEnvVars() map[string]string {
	envVars := make(map[string]string)
	envVars["foo"] = "bar"
	envVars["override_env_1"] = "foo"
	envVars["baz"] = "foo=bar"
	envVars["empty"] = ""
	envVars["override_env_2"] = "foo"
	return envVars
}

func expectedOverriddenCosEnvVars() map[string]string {
	envVars := make(map[string]string)
	envVars["override_env_1"] = "foo"
	envVars["override_env_2"] = "foo"
	return envVars
}
