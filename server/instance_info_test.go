package server

import (
	"testing"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

func TestGCEInstanceURL(t *testing.T) {
	tests := []struct {
		name string
		info *pb.GCEInstanceInfo
		want string
	}{
		{
			name: "nil info",
			info: nil,
			want: "https://www.googleapis.com/compute/v1/projects//zones//instances/",
		},
		{
			name: "human-readable instance URL",
			info: &pb.GCEInstanceInfo{
				Zone:          "us-central1-a",
				ProjectId:     "test-project-id",
				ProjectNumber: 123456,
				InstanceName:  "test-instance-name",
				InstanceId:    7890,
			},
			want: "https://www.googleapis.com/compute/v1/projects/test-project-id/zones/us-central1-a/instances/test-instance-name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GCEInstanceURL(tc.info); got != tc.want {
				t.Errorf("GCEInstanceURL(%v) = %q, want %q", tc.info, got, tc.want)
			}
		})
	}
}

func TestGCEInstanceResourceName(t *testing.T) {
	tests := []struct {
		name string
		info *pb.GCEInstanceInfo
		want string
	}{
		{
			name: "nil info",
			info: nil,
			want: "//compute.googleapis.com/projects/0/zones//instances/0",
		},
		{
			name: "numeric instance resource name",
			info: &pb.GCEInstanceInfo{
				Zone:          "us-central1-a",
				ProjectNumber: 1005225290969,
				InstanceId:    3433993572136660618,
			},
			want: "//compute.googleapis.com/projects/1005225290969/zones/us-central1-a/instances/3433993572136660618",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GCEInstanceResourceName(tc.info); got != tc.want {
				t.Errorf("GCEInstanceResourceName(%v) = %q, want %q", tc.info, got, tc.want)
			}
		})
	}
}
