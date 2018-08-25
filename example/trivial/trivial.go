package main

import (
	"fmt"
	"net/http"
	"net/url"

	"crypto/tls"
	"crypto/x509"

	"crypto/rsa"

	"github.com/erictg/saml/samlsp"
)

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.Token(r.Context()).Attributes.Get("cn"))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("/home/erictg97/mindstand_tech/saml_fork/src/github.com/erictg/saml/example/trivial/myservice.cert",
		"/home/erictg97/mindstand_tech/saml_fork/src/github.com/erictg/saml/example/trivial/myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("http://localhost:8000/metadata")
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		IDPMetadataURL: idpMetadataURL,
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
	})
	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	http.ListenAndServe(":8080", nil)
	c := make(chan bool)
	<- c
}
