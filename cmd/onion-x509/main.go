// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
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
						Action: CommandCA,
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
						Action: CommandCert,
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
