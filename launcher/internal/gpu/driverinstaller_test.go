package gpu

import (
	"testing"
)

func TestParseCCStatus(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    CCMode
		wantErr bool
	}{
		{
			name:    "CC ON",
			output:  "some text CC status: ON more text",
			want:    CCModeON,
			wantErr: false,
		},
		{
			name:    "CC OFF",
			output:  "another line CC status: OFF at the end",
			want:    CCModeOFF,
			wantErr: false,
		},
		{
			name:    "CC ON at the beginning",
			output:  "CC status: ON some other info",
			want:    CCModeON,
			wantErr: false,
		},
		{
			name:    "CC OFF only",
			output:  "CC status: OFF",
			want:    CCModeOFF,
			wantErr: false,
		},
		{
			name:    "CC status not found",
			output:  "No CC information here",
			want:    "",
			wantErr: true,
		},
		{
			name:    "CC status misspelled",
			output:  "CC state: ON",
			want:    "",
			wantErr: true,
		},
		{
			name:    "CC value missing",
			output:  "CC status:",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Invalid CC value",
			output:  "CC status: ENABLED",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Multiple CC status lines - picks the first",
			output:  "CC status: ON\nSome other info\nCC status: OFF",
			want:    CCModeON,
			wantErr: false,
		},
		{
			name:    "Case insensitive match",
			output:  "CC status: on",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Whitespace around CC value",
			output:  "CC status:  ON  ",
			want:    CCModeON,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCCStatus(tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCCStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseCCStatus() got = %v, want %v", got, tt.want)
			}
		})
	}
}
