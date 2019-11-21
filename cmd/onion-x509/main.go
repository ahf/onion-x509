// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"
)

func main() {
	app := &cli.App{
		Name:    "onion-x509",
		Usage:   "Onion x509 Utility.",
		Version: VERSION,
		Commands: []*cli.Command{
			{
				Name:  "ca",
				Usage: "Certificate Authority (CA) Handling.",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name:  "create",
						Usage: "Create a new Certificate Authority (CA) from an Onion service.",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "secret-key, s",
								Usage: "Path to the Onion service secret key file.",
								Value: "hs_ed25519_secret_key",
							},
							&cli.StringFlag{
								Name:  "output, o",
								Usage: "Path to the file that will contain the PEM-encoded CA certificate.",
								Value: "onion-ca.pem",
							},
							&cli.StringFlag{
								Name:        "valid-from",
								Usage:       "Date from which the CA should be valid from. Example: \"Jan 2 15:04:05 2006\".",
								Value:       "",
								DefaultText: "Current Timestamp",
							},
							&cli.DurationFlag{
								Name:  "valid-for",
								Usage: "How long should the CA be valid for.",
								Value: 10 * 365 * 24 * time.Hour,
							},
							&cli.StringFlag{
								Name:  "organization",
								Usage: "Name of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "country",
								Usage: "Country of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "province",
								Usage: "Province of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "locality",
								Usage: "Locality (city) of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "street-address",
								Usage: "Street address of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "postal-code",
								Usage: "Postal code of your organization.",
								Value: "",
							},
						},
						Action: func(c *cli.Context) error {
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
						},
					},
				},
			},
			{
				Name:  "cert",
				Usage: "Certificate Handling.",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name:  "create",
						Usage: "Create a new certificate signed by your Onion Certificate Authority.",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "secret-key, s",
								Usage: "Path to the Onion service secret key file.",
								Value: "hs_ed25519_secret_key",
							},
							&cli.StringFlag{
								Name:  "ca, c",
								Usage: "Path to your generated PEM-encoded Certificate Authority file.",
								Value: "onion-ca.pem",
							},
							&cli.StringFlag{
								Name:  "output, o",
								Usage: "Path to the file that will contain the PEM-encoded certificate.",
								Value: "onion-cert.pem",
							},
							&cli.StringFlag{
								Name:  "key, k",
								Usage: "Path to the file that will contain the PEM-encoded private key.",
								Value: "onion-cert-secret-key.pem",
							},
							&cli.StringFlag{
								Name:  "hostnames",
								Usage: "Comma separated list of hostnames. One '@' must be at the end of each hostname and expands to the Onion Service address.",
								Value: "@",
							},
							&cli.StringFlag{
								Name:        "valid-from",
								Usage:       "Date from which the CA should be valid from. Example: \"Jan 2 15:04:05 2006\".",
								Value:       "",
								DefaultText: "Current Timestamp",
							},
							&cli.DurationFlag{
								Name:  "valid-for",
								Usage: "How long should the CA be valid for.",
								Value: 2 * 365 * 24 * time.Hour,
							},
							&cli.StringFlag{
								Name:  "organization",
								Usage: "Name of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "country",
								Usage: "Country of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "province",
								Usage: "Province of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "locality",
								Usage: "Locality (city) of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "street-address",
								Usage: "Street address of your organization.",
								Value: "",
							},
							&cli.StringFlag{
								Name:  "postal-code",
								Usage: "Postal code of your organization.",
								Value: "",
							},
						},
						Action: func(c *cli.Context) error {
							// Load our ed25519 keys into memory.
							secretKeyPath := c.String("secret-key")
							log.Printf("Loading ed25519 keys from %s", secretKeyPath)

							keyPair, err := Ed25519KeyPairFromFile(secretKeyPath)

							if err != nil {
								log.Fatalf("Unable to load ed25519 keys from file %s: %s", secretKeyPath, err)
							}

							log.Printf("Loaded ed25519 keys for %s", OnionHostname(keyPair.PublicKey()))

							// Read our CA certificate.
							caFilePath := c.String("ca")
							log.Printf("Loading Certificate Authority from %s", caFilePath)
							caPEMData, err := ioutil.ReadFile(caFilePath)

							if err != nil {
								log.Fatalf("Unable to read CA file: %s", err)
							}

							caDERData, _ := pem.Decode(caPEMData)

							if caDERData == nil {
								log.Fatalf("Unable to decode PEM data from %s", caFilePath)
							}

							ca, err := x509.ParseCertificate(caDERData.Bytes)

							if err != nil {
								log.Fatalf("Unable to parse CA file: %s", err)
							}

							// Create our ed25519 TLS key pair that will be used for our new
							// certificate.
							log.Printf("Generating ed25519 keys for our certificate")
							certPublicKey, certSecretKey, err := ed25519.GenerateKey(rand.Reader)

							if err != nil {
								log.Fatalf("Unable to generate ed25519 keys for the certificate: %s", err)
							}

							certSecretKeyData, err := x509.MarshalPKCS8PrivateKey(certSecretKey)

							if err != nil {
								log.Fatalf("Unable to marshal ed25519 secret key: %s", err)
							}

							certSecretKeyPEM := new(bytes.Buffer)
							pem.Encode(certSecretKeyPEM, &pem.Block{
								Type:  "PRIVATE KEY",
								Bytes: certSecretKeyData,
							})

							certOutputKeyFile := c.String("key")
							log.Printf("Saving ed25519 secret key to %s", certOutputKeyFile)
							err = ioutil.WriteFile(certOutputKeyFile, certSecretKeyPEM.Bytes(), 0600)

							if err != nil {
								log.Fatalf("Unable to write ed25519 secret key file: %s", err)
							}

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

							cert := &x509.Certificate{
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
								KeyUsage:    x509.KeyUsageDigitalSignature,

								BasicConstraintsValid: true,
							}

							hostnames := strings.Split(c.String("hostnames"), ",")

							for _, hostname := range hostnames {
								cert.DNSNames = append(cert.DNSNames, SanitizeHostname(hostname, keyPair.PublicKey()))
							}

							log.Printf("Creating certificate")
							certDER, err := x509.CreateCertificate(rand.Reader, cert, ca, certPublicKey, keyPair)

							if err != nil {
								log.Fatalf("Unable to create certificate: %s", err)
							}

							// Encode our certificate from DER to PEM.
							certPEM := new(bytes.Buffer)
							pem.Encode(certPEM, &pem.Block{
								Type:  "CERTIFICATE",
								Bytes: certDER,
							})

							// Save it to disk.
							outputFile := c.String("output")
							log.Printf("Saving certificate to %s", outputFile)

							err = ioutil.WriteFile(outputFile, certPEM.Bytes(), 0600)

							if err != nil {
								log.Fatalf("Unable to write certificate to file: %s", err)
							}

							return nil
						},
					},
				},
			},
		},
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Alexander Færøy",
				Email: "ahf@torproject.org",
			},
		},
		Copyright: "(c) 2019 The Tor Project, Inc.",
	}

	err := app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}
