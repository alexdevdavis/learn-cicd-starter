package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header – missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey thisistheactualkey"},
			},
			wantKey: "thisistheactualkey",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error — %v, got error — %v", tt.wantErr, err)
			}
		})
	}
}
