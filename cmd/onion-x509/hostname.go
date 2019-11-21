// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"log"
	"strings"
)

func SanitizeHostname(hostname string, publicKey ed25519.PublicKey) string {
	h := strings.TrimSpace(hostname)

	count := strings.Count(h, "@")

	if count == 0 {
		log.Fatalf("Missing @ in hostname.")
	}

	if count > 1 {
		log.Fatalf("Maximum one @ is allowed per hostname")
	}

	if h[len(h)-1:] != "@" {
		log.Fatalf("Missing @ at the end of hostname: %s", hostname)
	}

	onion := OnionHostname(publicKey)

	r := strings.Replace(h, "@", onion, 1)

	return r
}
