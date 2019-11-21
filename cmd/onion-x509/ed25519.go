// Copyright (c) 2019 The Tor Project, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"io/ioutil"

	ed25519_go "crypto/ed25519"
	ed25519_tor "github.com/cretz/bine/torutil/ed25519"
)

func Ed25519KeyPairFromFile(path string) (*Ed25519KeyPair, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	// These files have a 32-byte header and a 64-byte key.
	if len(data) != 32+64 {
		return nil, errors.New("Invalid ed25519 secret key file size")
	}

	header := data[0:32]

	if !bytes.HasPrefix(header, []byte("== ed25519v1-secret: type0 ==")) {
		return nil, errors.New("Invalid header tag in ed25519 secret key file")
	}

	secretKey := ed25519_tor.PrivateKey(data[32:])
	publicKey := ed25519_go.PublicKey(secretKey.PublicKey())

	return &Ed25519KeyPair{secretKey, publicKey}, nil
}

type Ed25519KeyPair struct {
	// Secret Key, in Tor's ed25519 type.
	secretKey ed25519_tor.PrivateKey

	// Public Key, in Go's own ed25519 type.
	publicKey ed25519_go.PublicKey
}

func (keyPair *Ed25519KeyPair) Secret() ed25519_tor.PrivateKey {
	return keyPair.secretKey
}

func (keyPair *Ed25519KeyPair) Public() crypto.PublicKey {
	return keyPair.publicKey
}

func (keyPair *Ed25519KeyPair) PublicKey() ed25519_go.PublicKey {
	return keyPair.publicKey
}

func (keyPair *Ed25519KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed25519: cannot sign hashed message")
	}

	// We use Tor's ed25519 version for signing messages.
	return ed25519_tor.Sign(keyPair.secretKey, message), nil
}
