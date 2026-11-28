package app

import "testing"

// A site is issued by its own certificate_source; one created without it
// would get Let's Encrypt even where the installation uses its internal CA.
func TestNewSiteStartsWithTheDefaultCertificateSource(t *testing.T) {
	internal := newMap("site_defaults", newMap("certificate_source", "internal", "le_managed", false))
	cases := []struct {
		name       string
		site       *Map
		config     *Map
		wantSource any
		wantLE     any
	}{
		{"internal install", newMap("name", "a.example.test"), internal, "internal", false},
		{"letsencrypt install", newMap("name", "a.example.test"),
			newMap("site_defaults", newMap("certificate_source", "letsencrypt")), "letsencrypt", true},
		{"explicit source kept", newMap("name", "a.example.test", "certificate_source", "external"), internal, "external", nil},
		{"no defaults", newMap("name", "a.example.test"), newMap(), nil, nil},
		{"invalid default", newMap("name", "a.example.test"),
			newMap("site_defaults", newMap("certificate_source", "acme")), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startWithDefaultCertificateSource(tc.site, tc.config)
			if got := tc.site.Value("certificate_source"); got != tc.wantSource {
				t.Fatalf("certificate_source = %v, want %v", got, tc.wantSource)
			}
			if got := tc.site.Value("le_managed"); got != tc.wantLE {
				t.Fatalf("le_managed = %v, want %v", got, tc.wantLE)
			}
		})
	}
}
