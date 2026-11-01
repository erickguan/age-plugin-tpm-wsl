// Independent test oracle: no project code or Rust HPKE implementation is used.
// Requires Go 1.26+. All plaintexts and the fixed receiver scalar are public fixtures.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
)

// Published CFRG RFC 9180 suite 16/1/3 receiver scalar; never a production key.
const fixtureScalar = "a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b"
const fixturePlaintext = "000102030405060708090a0b0c0d0e0f"

type record struct {
	Generator       string `json:"generator"`
	ReceiverPrivate string `json:"receiver_private,omitempty"`
	Recipient       string `json:"recipient"`
	Fingerprint     string `json:"fingerprint"`
	Info            string `json:"info"`
	AAD             string `json:"aad"`
	Plaintext       string `json:"plaintext"`
	Body            string `json:"body"`
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func decode(text string) []byte { return must(hex.DecodeString(text)) }

// Construct the application's transcript from its written specification.
func transcript(recipient []byte) (fingerprint string, info, aad []byte) {
	if len(recipient) != 68 || !bytes.Equal(recipient[:3], []byte{2, 0, 1}) {
		panic("expected version 2, suite 1, canonical P-256 recipient")
	}
	must(ecdh.P256().NewPublicKey(recipient[3:]))
	digest := sha256.Sum256(recipient)
	fingerprint = base64.RawStdEncoding.EncodeToString(digest[:])
	info = append([]byte("age-plugin-tpm-wsl/HPKE-v2\x00"), recipient...)
	aad = []byte("tpm-wsl-hpke 2 " + fingerprint)
	return
}

func main() {
	generate := flag.Bool("generate", false, "generate a public software fixture")
	recipientHex := flag.String("recipient", "", "wrap a public test value for this hex recipient")
	verify := flag.String("verify", "", "verify a saved fixture's transcript and authenticated plaintext")
	flag.Parse()
	if flag.NArg() != 0 {
		panic("unexpected arguments")
	}
	modes := 0
	for _, enabled := range []bool{*generate, *recipientHex != "", *verify != ""} {
		if enabled {
			modes++
		}
	}
	if modes != 1 {
		panic("select exactly one of --generate, --recipient or --verify")
	}
	if *verify != "" {
		var saved record
		if err := json.Unmarshal(must(os.ReadFile(*verify)), &saved); err != nil {
			panic(err)
		}
		fingerprint, info, aad := transcript(decode(saved.Recipient))
		if fingerprint != saved.Fingerprint || !bytes.Equal(info, decode(saved.Info)) || !bytes.Equal(aad, decode(saved.AAD)) {
			panic("literal application transcript mismatch")
		}
		private := must(ecdh.P256().NewPrivateKey(decode(saved.ReceiverPrivate)))
		if !bytes.Equal(private.PublicKey().Bytes(), decode(saved.Recipient)[3:]) {
			panic("fixture receiver mismatch")
		}
		body := decode(saved.Body)
		if len(body) != 97 {
			panic("incorrect body length")
		}
		receiver := must(hpke.NewRecipient(body[:65], must(hpke.NewDHKEMPrivateKey(private)), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info))
		if !bytes.Equal(must(receiver.Open(aad, body[65:])), decode(saved.Plaintext)) {
			panic("fixture plaintext mismatch")
		}
		fmt.Println("Independent Go HPKE fixture and literal transcript verified")
		return
	}
	var scalar string
	if *generate {
		scalar = fixtureScalar
		private := must(ecdh.P256().NewPrivateKey(decode(scalar)))
		*recipientHex = hex.EncodeToString(append([]byte{2, 0, 1}, private.PublicKey().Bytes()...))
	}
	recipient := decode(*recipientHex)
	fingerprint, info, aad := transcript(recipient)
	public := must(ecdh.P256().NewPublicKey(recipient[3:]))
	enc, sender, err := hpke.NewSender(must(hpke.NewDHKEMPublicKey(public)), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		panic(err)
	}
	ciphertext := must(sender.Seal(aad, decode(fixturePlaintext)))
	output := record{
		Generator: "Go standard library crypto/hpke " + runtime.Version(), ReceiverPrivate: scalar,
		Recipient: *recipientHex, Fingerprint: fingerprint, Info: hex.EncodeToString(info),
		AAD: hex.EncodeToString(aad), Plaintext: fixturePlaintext,
		Body: hex.EncodeToString(append(enc, ciphertext...)),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		panic(err)
	}
}
