package webmirror

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// LANPort is where the web mirror also listens, on every address and over
// HTTPS, when it has a CA (Options.LANCA): phones on the local network
// open it at https://<this computer's LAN address>:LANPort/.
const LANPort = "7467"

// leafLife is how long a certificate the CA signs for a LAN address lasts;
// a new one is made when less than leafRenew of it is left.
const (
	leafLife  = 90 * 24 * time.Hour
	leafRenew = 7 * 24 * time.Hour
)

// CA signs the web mirror's certificates for its LAN addresses. The phone
// that opens the page must trust it.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer

	mu    sync.Mutex
	leafs map[string]*tls.Certificate // by IP
}

// LoadCA reads a CA from a PEM file holding its CERTIFICATE and its
// PKCS#8 PRIVATE KEY. It returns nil, nil when there is no such file.
func LoadCA(path string) (*CA, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca := &CA{leafs: map[string]*tls.Certificate{}}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			if ca.cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("%s: the key cannot sign", path)
			}
			ca.key = s
		}
	}
	if ca.cert == nil || ca.key == nil {
		return nil, fmt.Errorf("%s: needs a CERTIFICATE and a PRIVATE KEY", path)
	}
	if !ca.cert.IsCA {
		return nil, fmt.Errorf("%s: the certificate is not a CA", path)
	}
	return ca, nil
}

// certificate returns a certificate for the address the browser reached,
// signed by the CA, making one when there is none or it is old.
func (ca *CA) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	addr, ok := hello.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("not a TCP connection")
	}
	ip := addr.IP.String()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c := ca.leafs[ip]; c != nil && time.Until(c.Leaf.NotAfter) > leafRenew {
		return c, nil
	}
	c, err := ca.sign(addr.IP)
	if err != nil {
		return nil, err
	}
	ca.leafs[ip] = c
	return c, nil
}

func (ca *CA) sign(ip net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ip.String()},
		IPAddresses:  []net.IP{ip},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// lanKey marks a request that came in on the LAN listener and names the
// address it reached.
type lanKey struct{}

// lanHandler serves h on the LAN listener: only to requests whose Host is
// the very address they reached (no DNS name, so no DNS rebinding), which
// the mirror then takes as this computer's own and not proxied.
func lanHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		ip := net.ParseIP(host)
		if local == nil || ip == nil || !ip.Equal(local.IP) {
			http.Error(w, "Pinky's web mirror answers on the local network only at this computer's address.", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), lanKey{}, true)))
	})
}

// fromLAN reports whether r came in on the LAN listener (lanHandler).
func fromLAN(r *http.Request) bool {
	on, _ := r.Context().Value(lanKey{}).(bool)
	return on
}

// lanIP returns this computer's first private IPv4 address on an
// interface that is up, nil when it has none.
func lanIP() net.IP {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if ok && n.IP.To4() != nil && n.IP.IsPrivate() {
				return n.IP
			}
		}
	}
	return nil
}
