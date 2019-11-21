// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"testing"
)

func TestOnionHostname(t *testing.T) {
	publicKeyData := []byte{0x2d, 0xe0, 0x28, 0xde, 0xfd, 0x82, 0x78, 0x0b, 0x7e, 0xeb, 0x58, 0x14, 0xad, 0x41, 0x14, 0xbe, 0xbc, 0x35, 0x49, 0x10, 0x4e, 0x07, 0x82, 0x07, 0x86, 0x2c, 0x36, 0x5f, 0xd8, 0xb2, 0xf7, 0x70}
	publicKey := ed25519.PublicKey(publicKeyData)

	if OnionHostname(publicKey) != "fxqcrxx5qj4aw7xllakk2qiux26dksiqjydyeb4gfq3f7wfs65yooaad.onion" {
		t.Errorf("Onion hostname was incorrect.")
	}
}
