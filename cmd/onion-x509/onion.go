// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"strings"

	"golang.org/x/crypto/sha3"
)

func OnionHostname(publicKey ed25519.PublicKey) string {
	s := []byte(".onion checksum")
	s = append(s, publicKey...)
	s = append(s, byte(3))
	checksum := sha3.Sum256(s)

	r := publicKey[:]
	r = append(r, checksum[0:2]...)
	r = append(r, byte(3))

	return strings.ToLower(base32.StdEncoding.EncodeToString(r)) + ".onion"
}
