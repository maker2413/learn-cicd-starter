package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     http.Header
		wantKey    string
		expectErr  bool
		errMessage string
	}{
		{
			name:       "No Authorization Header",
			header:     http.Header{},
			wantKey:    "",
			expectErr:  true,
			errMessage: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed Authorization Header - Wrong Prefix",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer sometoken")
				return h
			}(),
			wantKey:    "",
			expectErr:  true,
			errMessage: "malformed authorization header",
		},
		{
			name: "Valid Authorization Header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey test-api-key-123")
				return h
			}(),
			wantKey:   "test-api-key-123",
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.header)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if err.Error() != tc.errMessage {
					t.Errorf("expected error message %q, got %q", tc.errMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("did not expect error, got: %v", err)
				}
				if key != tc.wantKey {
					t.Errorf("expected key %q, got %q", tc.wantKey, key)
				}
			}
		})
	}
}
