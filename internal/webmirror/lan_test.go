package webmirror

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCA writes a fresh CA as LoadCA reads it and returns its file.
func writeCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	out := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCAMissing(t *testing.T) {
	ca, err := LoadCA(filepath.Join(t.TempDir(), "none.pem"))
	if ca != nil || err != nil {
		t.Fatalf("LoadCA(missing) = %v, %v; want nil, nil", ca, err)
	}
}

func TestCASignsForTheAddress(t *testing.T) {
	ca, err := LoadCA(writeCA(t))
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.168.1.20")
	c, err := ca.sign(ip)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: ip.String(), Roots: roots}); err != nil {
		t.Fatalf("the leaf does not verify for %s: %v", ip, err)
	}
}

func TestLANHandlerTakesOnlyTheAddressReached(t *testing.T) {
	var lan bool
	h := lanHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lan = fromLAN(r) && !proxied(r)
	}))
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.20"), Port: 7467}
	for _, tc := range []struct {
		host string
		want int
	}{
		{"192.168.1.20:7467", http.StatusOK},
		{"192.168.1.21:7467", http.StatusForbidden},
		{"evil.example:7467", http.StatusForbidden},
	} {
		lan = false
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tc.host
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("Host %s: status %d, want %d", tc.host, w.Code, tc.want)
		}
		if lan != (tc.want == http.StatusOK) {
			t.Errorf("Host %s: taken as LAN and not proxied = %v", tc.host, lan)
		}
	}
}
