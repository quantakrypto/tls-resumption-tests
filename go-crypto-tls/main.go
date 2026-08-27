// Does Go's crypto/tls re-establish, on a RESUMED connection, conditions that a full
// handshake evaluated? Two conditions, one process, no waiting on wall-clock certificates
// for the second.
//
//  A. CLIENT CERTIFICATE EXPIRY. Establish a session with a client certificate valid for a
//     few seconds, let it expire, then resume. Compare against a full handshake, which must
//     fail. This is the same experiment the OpenSSL harness runs.
//  B. TRUST ANCHOR REMOVAL. Establish a session, then remove the issuing root from the
//     server's ClientCAs and resume. Go 1.25.7 / 1.24.13 (Feb 2026) added a root-membership
//     check on resumption; this is the test of that fix.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

func mkCert(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	notAfter time.Time, isCA bool, clientAuth bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if clientAuth {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else if !isCA {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	}
	p, pk := tmpl, key
	if parent != nil {
		p, pk = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p, &key.PublicKey, pk)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key, der
}

func main() {
	fmt.Printf("Go %s, %s/%s\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	const shortLife = 12 * time.Second

	caCert, caKey, caDER := mkCert("Test CA", nil, nil, time.Now().Add(time.Hour), true, false)
	srvCert, srvKey, srvDER := mkCert("localhost", caCert, caKey, time.Now().Add(time.Hour), false, false)
	cliCert, cliKey, cliDER := mkCert("test-client", caCert, caKey, time.Now().Add(shortLife), false, true)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	empty := x509.NewCertPool() // the same pool minus the root, for experiment B

	// dropRoot flips the server's ClientCAs between connections without restarting the
	// listener, so the ticket key and session cache stay identical. Only the trust
	// configuration changes, which is the variable under test.
	var dropRoot atomic.Bool
	base := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey, Leaf: srvCert}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srvConf := &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		if dropRoot.Load() {
			c.ClientCAs = empty
		} else {
			c.ClientCAs = roots
		}
		return c, nil
	}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvConf)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				c.Write([]byte("ok"))
				time.Sleep(150 * time.Millisecond)
			}(c)
		}
	}()

	cache := tls.NewLRUClientSessionCache(8)
	dial := func() (bool, error) {
		conf := &tls.Config{
			RootCAs:            roots,
			Certificates:       []tls.Certificate{{Certificate: [][]byte{cliDER}, PrivateKey: cliKey, Leaf: cliCert}},
			ClientSessionCache: cache,
			ServerName:         "localhost",
			MinVersion:         tls.VersionTLS13,
		}
		c, err := tls.Dial("tcp", ln.Addr().String(), conf)
		if err != nil {
			return false, err
		}
		defer c.Close()
		buf := make([]byte, 2)
		if _, err := c.Read(buf); err != nil { // TLS 1.3 surfaces server alerts on first read
			return c.ConnectionState().DidResume, err
		}
		return c.ConnectionState().DidResume, nil
	}
	report := func(label string, resumed bool, err error) {
		status := "ACCEPTED"
		if err != nil {
			status = "REJECTED (" + err.Error() + ")"
		}
		kind := "full handshake"
		if resumed {
			kind = "RESUMED"
		}
		fmt.Printf("  %-52s %-15s %s\n", label, kind, status)
	}

	fmt.Println("A. CLIENT CERTIFICATE EXPIRY")
	r, e := dial()
	report("1. valid client certificate, first connection", r, e)
	r, e = dial()
	report("2. valid client certificate, resumed (baseline)", r, e)
	_ = caDER
	fmt.Printf("     waiting %s for the client certificate to expire...\n", shortLife)
	time.Sleep(shortLife + 2*time.Second)
	r, e = dial()
	report("3. EXPIRED client certificate, resumed", r, e)
	cache2 := tls.NewLRUClientSessionCache(8)
	old := cache
	cache = cache2
	r, e = dial()
	report("4. EXPIRED client certificate, full handshake (control)", r, e)
	cache = old

	fmt.Println("\nB. TRUST ANCHOR REMOVED FROM ClientCAs")
	cliCert, cliKey, cliDER = mkCert("test-client-2", caCert, caKey, time.Now().Add(time.Hour), false, true)
	cache = tls.NewLRUClientSessionCache(8)
	r, e = dial()
	report("1. root present, first connection", r, e)
	r, e = dial()
	report("2. root present, resumed (baseline)", r, e)
	dropRoot.Store(true)
	r, e = dial()
	report("3. root REMOVED, resumed", r, e)
	cache = tls.NewLRUClientSessionCache(8)
	r, e = dial()
	report("4. root REMOVED, full handshake (control)", r, e)
}
