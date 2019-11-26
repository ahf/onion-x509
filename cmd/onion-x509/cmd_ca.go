// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"time"

	"github.com/urfave/cli"
)

func CommandCA(c *cli.Context) error {
	// Load our ed25519 keys into memory.
	secretKeyPath := c.String("secret-key")
	log.Printf("Loading ed25519 keys from %s", secretKeyPath)

	keyPair, err := Ed25519KeyPairFromFile(secretKeyPath)

	if err != nil {
		log.Fatalf("Unable to load ed25519 keys from file %s: %s", secretKeyPath, err)
	}

	log.Printf("Loaded ed25519 keys for %s", OnionHostname(keyPair.PublicKey()))

	// Generate our CA certificate.
	notBefore := time.Now()
	validFromString := c.String("valid-from")
	validFor := c.Duration("valid-for")

	if validFromString != "" {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFromString)

		if err != nil {
			log.Fatalf("Unable to parse valid-from date: %s", err)
		}
	}

	notAfter := notBefore.Add(validFor)

	ca := &x509.Certificate{
		SerialNumber: RandomSerialNumber(),
		Subject: pkix.Name{
			Organization:  []string{c.String("organization")},
			Country:       []string{c.String("country")},
			Province:      []string{c.String("province")},
			Locality:      []string{c.String("locality")},
			StreetAddress: []string{c.String("street-address")},
			PostalCode:    []string{c.String("postal-code")},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	log.Printf("Creating CA certificate")
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, keyPair.Public(), keyPair)

	if err != nil {
		log.Fatalf("Unable to create CA certificate: %s", err)
	}

	// Encode our CA certificate from DER to PEM.
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})

	// Save it to disk.
	outputFile := c.String("output")
	log.Printf("Saving Certificate Authority to %s", outputFile)

	err = ioutil.WriteFile(outputFile, caPEM.Bytes(), 0600)

	if err != nil {
		log.Fatalf("Unable to write certificate authority to file: %s", err)
	}

	return nil
}
