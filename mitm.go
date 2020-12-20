package mitm

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Options struct {
	Dir   string
	Lease time.Duration

	CA     *tls.Certificate
	Handle http.HandlerFunc
}

type Proxy struct {
	dir string
	ca  *tls.Certificate
	fn  http.HandlerFunc
}

func New(opt Options) (*Proxy, error) {
	if opt.Dir == "" {
		opt.Dir = os.TempDir()
	}
	if opt.Handle == nil {
		return nil, fmt.Errorf("invalid nil post-process handler function")
	}
	p := &Proxy{
		dir: opt.Dir,
		ca:  opt.CA,
		fn:  opt.Handle,
	}
	return p, nil
}

func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		if p.fn != nil {
			p.fn(w, r)
		}
		return
	}
	p.takeover(w, r)
}

func (p Proxy) takeover(w http.ResponseWriter, r *http.Request) {
	if p.ca == nil || len(p.ca.Certificate) < 1 {
		http.Error(w, "invalid CA certificate", http.StatusInternalServerError)
		return
	}
	if p.ca.Leaf == nil {
		var err error
		p.ca.Leaf, err = x509.ParseCertificate(p.ca.Certificate[0])
		if err != nil {
			http.Error(w, "invalid CA certificate", http.StatusInternalServerError)
			return
		}
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cert, err := hostCert(p.ca, p.dir, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)

	tlsConfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	hijack, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sconn := tls.Server(hijack, tlsConfg)
	defer sconn.Close()
	sconn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// create a mitm ResponseWriter
	mw := &mitmResponseWriter{
		header: make(http.Header),
		writer: bufio.NewWriter(sconn),
	}
	defer mw.Flush()

	// read from hijacked connection
	bufReader := bufio.NewReader(sconn)
	mr, err := http.ReadRequest(bufReader)
	if err != nil {
		http.Error(mw, err.Error(), http.StatusBadRequest)
		return
	}

	p.fn(mw, mr)
}

type mitmResponseWriter struct {
	writer *bufio.Writer
	header http.Header

	wroteHeader bool
}

func (w mitmResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	statusText := http.StatusText(statusCode)
	w.writer.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
}

func (w *mitmResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		for k := range w.header {
			val := w.header.Get(k)
			w.writer.WriteString(fmt.Sprintf("%s: %s\r\n", k, val))
		}
		w.wroteHeader = true
		w.writer.Write([]byte("\r\n"))
	}
	return w.writer.Write(data)
}

func (w mitmResponseWriter) Header() http.Header {
	return w.header
}

func (w mitmResponseWriter) Flush() error {
	return w.writer.Flush()
}

func randomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber, err
}

const (
	pemCertTpl = "%s_crt.pem"
	pemKeyTpl  = "%s_key.pem"
)

func isFileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	return true
}

func certFromFile(dir, host string) (*tls.Certificate, error) {
	certFile := filepath.Join(dir, fmt.Sprintf(pemCertTpl, host))
	keyFile := filepath.Join(dir, fmt.Sprintf(pemKeyTpl, host))
	if !isFileExists(certFile) || !isFileExists(keyFile) {
		return nil, fmt.Errorf("file not exists")
	}

	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	tlsCert := &tls.Certificate{
		Certificate: append([][]byte{}, cert.Raw),
		PrivateKey:  priv,
	}
	return tlsCert, nil
}

func certToFile(cert *tls.Certificate, dir, host string) error {
	if cert == nil || len(cert.Certificate) < 1 {
		return fmt.Errorf("invalid certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	privDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	certFile := filepath.Join(dir, fmt.Sprintf(pemCertTpl, host))
	if err = ioutil.WriteFile(certFile, certPEM, 0644); err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	keyFile := filepath.Join(dir, fmt.Sprintf(pemKeyTpl, host))
	if err = ioutil.WriteFile(keyFile, privPEM, 0600); err != nil {
		return err
	}
	return nil
}

func isValidCert(ca, cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) < 1 {
		return false
	}
	var err error
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return false
	}
	pool.AddCert(ca.Leaf)

	opts := x509.VerifyOptions{
		Roots: pool,
	}
	_, err = cert.Leaf.Verify(opts)
	if err != nil {
		return false
	}

	return true
}

func hostCert(ca *tls.Certificate, dir, host string) (*tls.Certificate, error) {
	cert, err := certFromFile(dir, host)
	if err == nil {
		if isValidCert(ca, cert) {
			return cert, nil
		}
	}
	cert, err = certNew(ca, host)
	if err != nil {
		return nil, err
	}
	if !isValidCert(ca, cert) {
		return nil, fmt.Errorf("certificate is invalid")
	}
	if err = certToFile(cert, dir, host); err != nil {
		fmt.Printf("Store cert for %s failed, %v\n", host, err)
	}
	return cert, nil
}

const (
	certOrg  = "MITM Certificate"
	certUnit = "MITM"
)

func certNew(ca *tls.Certificate, host string) (*tls.Certificate, error) {
	expiration := time.Now().AddDate(2, 3, 0)

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         host,
			Organization:       []string{certOrg},
			OrganizationalUnit: []string{certUnit},
		},
		NotBefore: time.Now(), NotAfter: expiration,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	parent, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}

	var priv crypto.PrivateKey
	switch ca.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519.PrivateKey:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case *rsa.PrivateKey:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}
	pub := priv.(crypto.Signer).Public()
	cert, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: append([][]byte{}, cert),
		PrivateKey:  priv,
	}
	return tlsCert, nil
}
