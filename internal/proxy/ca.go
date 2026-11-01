package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is the local certificate authority used to inspect HTTPS for hosts that
// have a request rule.
//
// Scope is the point. A CA that can mint certificates for any name is a
// powerful thing to have lying around, so this one:
//   - is generated per proxy run, in memory, unless the caller asks for it to
//     be written out (the runner writes only the PUBLIC certificate, into the
//     sandbox's private scratch directory, for the program to trust);
//   - carries a NameConstraints extension listing ONLY the hosts that have
//     rules, so even if its key leaked, clients that honour constraints would
//     reject a certificate it signed for any other name;
//   - is never added to the system trust store. Only the sandboxed program,
//     via SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE, trusts it.
//
// Hosts without a rule are never intercepted; their TLS goes end to end.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// NewCA creates an in-memory CA constrained to the given host patterns
// (leading-dot patterns constrain to the domain and its subdomains).
func NewCA(hosts []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var permitted []string
	for _, h := range hosts {
		permitted = append(permitted, trimDot(h))
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "SandboxCheckr proxy inspection CA (this run only)"},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(7 * 24 * time.Hour),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cache:   map[string]*tls.Certificate{},
	}, nil
}

// CertPEM is the public certificate, for the sandboxed program to trust.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// WriteCert writes the PUBLIC certificate to path with 0644. The private key
// never leaves the proxy process.
func (ca *CA) WriteCert(path string) error {
	return WriteFileNoFollow(path, ca.certPEM, 0o644)
}

// leaf returns a certificate for host signed by the CA.
func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing certificate for %s: %w", host, err)
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	ca.cache[host] = c
	return c, nil
}

func trimDot(h string) string {
	if len(h) > 0 && h[0] == '.' {
		return h[1:]
	}
	if len(h) > 1 && h[0] == '*' && h[1] == '.' {
		return h[2:]
	}
	return h
}
