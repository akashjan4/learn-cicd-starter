package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid API key",
			authHeader:  "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong authorization scheme",
			authHeader:  "Bearer my-token",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "missing API key",
			authHeader:  "ApiKey",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "empty authorization value",
			authHeader:  "ApiKey ",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "extra values after API key",
			authHeader:  "ApiKey my-secret-key extra",
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if tt.expectedErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.expectedErr)
				}

				if err.Error() != tt.expectedErr.Error() {
					t.Fatalf("expected error %q, got %q", tt.expectedErr, err)
				}

				if key != "" {
					t.Fatalf("expected empty key, got %q", key)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
