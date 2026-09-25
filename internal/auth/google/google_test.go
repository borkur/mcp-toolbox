// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestInitialize_Validation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "only clientID, mcpEnabled false",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				ClientID:   "my-client-id",
				McpEnabled: false,
			},
			wantError: false,
		},
		{
			name: "only audience, mcpEnabled false (disallowed)",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				Audience:   "my-audience",
				McpEnabled: false,
			},
			wantError: true,
		},
		{
			name: "only audience, mcpEnabled true (allowed)",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				Audience:   "my-audience",
				McpEnabled: true,
			},
			wantError: false,
		},
		{
			name: "scopesRequired, mcpEnabled false (disallowed)",
			config: Config{
				Name:           "google-auth",
				Type:           "google",
				ScopesRequired: []string{"scope"},
				McpEnabled:     false,
			},
			wantError: true,
		},
		{
			name: "scopesRequired, mcpEnabled true, with audience (allowed)",
			config: Config{
				Name:           "google-auth",
				Type:           "google",
				ScopesRequired: []string{"scope"},
				Audience:       "my-audience",
				McpEnabled:     true,
			},
			wantError: false,
		},
		{
			name: "scopesRequired, mcpEnabled true, without audience or clientID (disallowed)",
			config: Config{
				Name:           "google-auth",
				Type:           "google",
				ScopesRequired: []string{"scope"},
				McpEnabled:     true,
			},
			wantError: true,
		},
		{
			name: "both clientID and audience, mcpEnabled true",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				ClientID:   "my-client-id",
				Audience:   "my-audience",
				McpEnabled: true,
			},
			wantError: false,
		},
		{
			name: "neither clientID nor audience, mcpEnabled false",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				McpEnabled: false,
			},
			wantError: false,
		},
		{
			name: "neither clientID nor audience, mcpEnabled true (disallowed)",
			config: Config{
				Name:       "google-auth",
				Type:       "google",
				McpEnabled: true,
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.config.Initialize()
			if (err != nil) != tc.wantError {
				t.Fatalf("Initialize() returned error: %v, wantError: %v", err, tc.wantError)
			}
		})
	}
}

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (f mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestValidateMCPAuth_Opaque_Fallback(t *testing.T) {
	tests := []struct {
		name         string
		audience     string
		clientID     string
		tokenInfoAud string
		tokenInfoAzp string
		wantError    bool
	}{
		{
			name:         "only audience matches",
			audience:     "my-aud",
			tokenInfoAud: "my-aud",
			wantError:    false,
		},
		{
			name:         "only clientID matches (fallback)",
			clientID:     "my-client-id",
			tokenInfoAud: "my-client-id",
			wantError:    false,
		},
		{
			name:         "only clientID, tokenInfo uses azp (fallback)",
			clientID:     "my-client-id",
			tokenInfoAzp: "my-client-id",
			wantError:    false,
		},
		{
			name:         "both audience and clientID, audience matches",
			audience:     "my-aud",
			clientID:     "my-client-id",
			tokenInfoAud: "my-aud",
			wantError:    false,
		},
		{
			name:         "both audience and clientID, clientID does not fall back if audience is specified",
			audience:     "my-aud",
			clientID:     "my-client-id",
			tokenInfoAud: "my-client-id",
			wantError:    true,
		},
		{
			name:         "neither audience nor clientID specified",
			tokenInfoAud: "any-aud",
			wantError:    false,
		},
		{
			name:         "audience mismatch",
			audience:     "my-aud",
			tokenInfoAud: "wrong-aud",
			wantError:    true,
		},
		{
			name:         "clientID mismatch (fallback)",
			clientID:     "my-client-id",
			tokenInfoAud: "wrong-aud",
			wantError:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &http.Client{
				Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != "https://oauth2.googleapis.com/tokeninfo" {
						return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
					}
					respBody := fmt.Sprintf(`{"aud": %q, "azp": %q, "scope": "openid email"}`, tc.tokenInfoAud, tc.tokenInfoAzp)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(respBody)),
						Header:     make(http.Header),
					}, nil
				}),
			}

			a := AuthService{
				Config: Config{
					Audience: tc.audience,
					ClientID: tc.clientID,
				},
				client: mockClient,
			}

			header := make(http.Header)
			header.Set("Authorization", "Bearer some-opaque-token")

			_, err := a.ValidateMCPAuth(context.Background(), header)
			if (err != nil) != tc.wantError {
				t.Fatalf("ValidateMCPAuth() returned error: %v, wantError: %v", err, tc.wantError)
			}
		})
	}
}

func TestGetClaimsFromHeader_OpaqueAccessToken(t *testing.T) {
	tests := []struct {
		name         string
		headerVal    string
		clientID     string
		tokenInfoAud string
		tokenInfoAzp string
		tokenEmail   string
		statusCode   int
		wantError    bool
		wantEmail    string
	}{
		{
			name:      "no token header",
			headerVal: "",
			clientID:  "my-client-id",
			wantError: false,
			wantEmail: "",
		},
		{
			name:         "exact clientID match",
			headerVal:    "ya29.some-opaque-token",
			clientID:     "786365316782-930dpe.apps.googleusercontent.com",
			tokenInfoAud: "786365316782-930dpe.apps.googleusercontent.com",
			tokenEmail:   "borkur@pythian.com",
			statusCode:   http.StatusOK,
			wantError:    false,
			wantEmail:    "borkur@pythian.com",
		},
		{
			name:         "project prefix match between different client IDs",
			headerVal:    "ya29.some-opaque-token",
			clientID:     "786365316782-930dpe0c2hha1p81svj6t80v7n7305lu.apps.googleusercontent.com",
			tokenInfoAud: "786365316782-schg1ho6ejng33jmnd6f472arkc0fsak.apps.googleusercontent.com",
			tokenEmail:   "borkur@pythian.com",
			statusCode:   http.StatusOK,
			wantError:    false,
			wantEmail:    "borkur@pythian.com",
		},
		{
			name:         "token with Bearer prefix stripped",
			headerVal:    "Bearer ya29.some-opaque-token",
			clientID:     "786365316782-930dpe.apps.googleusercontent.com",
			tokenInfoAud: "786365316782-930dpe.apps.googleusercontent.com",
			tokenEmail:   "borkur@pythian.com",
			statusCode:   http.StatusOK,
			wantError:    false,
			wantEmail:    "borkur@pythian.com",
		},
		{
			name:         "audience mismatch from different project",
			headerVal:    "ya29.some-opaque-token",
			clientID:     "786365316782-930dpe.apps.googleusercontent.com",
			tokenInfoAud: "999999999999-other.apps.googleusercontent.com",
			statusCode:   http.StatusOK,
			wantError:    true,
		},
		{
			name:       "tokeninfo error response 400",
			headerVal:  "ya29.invalid-token",
			clientID:   "786365316782-930dpe.apps.googleusercontent.com",
			statusCode: http.StatusBadRequest,
			wantError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &http.Client{
				Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != "https://oauth2.googleapis.com/tokeninfo" {
						return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
					}
					status := tc.statusCode
					if status == 0 {
						status = http.StatusOK
					}
					if status != http.StatusOK {
						return &http.Response{
							StatusCode: status,
							Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_token"}`)),
							Header:     make(http.Header),
						}, nil
					}
					respBody := fmt.Sprintf(`{"aud": %q, "azp": %q, "email": %q, "scope": "openid email"}`, tc.tokenInfoAud, tc.tokenInfoAzp, tc.tokenEmail)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(respBody)),
						Header:     make(http.Header),
					}, nil
				}),
			}

			a := AuthService{
				Config: Config{
					Name:     "google-auth",
					ClientID: tc.clientID,
				},
				client: mockClient,
			}

			header := make(http.Header)
			if tc.headerVal != "" {
				header.Set("google-auth_token", tc.headerVal)
			}

			claims, err := a.GetClaimsFromHeader(context.Background(), header)
			if (err != nil) != tc.wantError {
				t.Fatalf("GetClaimsFromHeader() returned error: %v, wantError: %v", err, tc.wantError)
			}
			if !tc.wantError && tc.wantEmail != "" {
				if claims == nil {
					t.Fatalf("GetClaimsFromHeader() returned nil claims, expected email %s", tc.wantEmail)
				}
				if email, _ := claims["email"].(string); email != tc.wantEmail {
					t.Fatalf("GetClaimsFromHeader() email = %q, want %q", email, tc.wantEmail)
				}
			}
		})
	}
}
