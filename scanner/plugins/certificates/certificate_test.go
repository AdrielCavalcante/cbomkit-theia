// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"crypto/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	x509lib "github.com/cbomkit/cbomkit-theia/scanner/x509"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestIssue140_CombinedPEMFile(t *testing.T) {
	// A combined file containing both a private key and a certificate
	// The certificate plugin should find the certificate even though
	// it's in a file with a non-certificate extension
	combinedPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBZ2gHaRGWJXjLN6Lxoob\n" +
		"XRn6jNrVPGx2Smxfnwh/K7gRqRBMToBJ6MW8A3C0m7LLGVlN7XuULAlWMBuSJlr5\n" +
		"d2pJxR3N6oFhMMUOuFMGJOjSk3CRljaKzRoSNl8lDB2L4oqI0t7bCgXBaEMH3bmd\n" +
		"NIqnATOC/WQHmJaTmXdkHFJDOKB1GQGqSBiEOYhSq8bO8F2APbnlMHR8lhIrNNBZ\n" +
		"m9r4fMaV1jOKDQwNjkb5MUPKk8LMPkVJfhvfAKnDnVOG2U7R7DBfaW6hEOK3liT\n" +
		"YMEf0cfIfn3caVVhF6m7+oFMnPkwIDAQABAoIBAC5RgZ+hBx7xHNaEjMGq0vRE\n" +
		"-----END RSA PRIVATE KEY-----\n" +
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIB3DCCAYOgAwIBAgINAgPlfvU/k/2lCSGypjAKBggqhkjOPQQDAjBQMSQwIgYD\n" +
		"VQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjQxEzARBgNVBAoTCkdsb2Jh\n" +
		"bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTIxMTEzMDAwMDAwWhcNMzgw\n" +
		"MTE5MDMxNDA3WjBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0g\n" +
		"UjQxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wWTAT\n" +
		"BgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4xnnTj2wlDp8uORkcA6SumuU5BwkWymOx\n" +
		"uYb4ilfBV85C+nOh92VC/x7BALJucw7/xyHlGKSq2XE/qNS5zowdo0IwQDAOBgNV\n" +
		"HQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUVLB7rUW44kB/\n" +
		"+wpu+74zyTyjhNUwCgYIKoZIzj0EAwIDRwAwRAIgIk90crlgr/HmnKAWBVBfw147\n" +
		"bmF0774BxL4YSFlhgjICICadVGNA3jdgUM/I2O2dgq43mLyjj0xMqTQrbO/7lZsm\n" +
		"-----END CERTIFICATE-----\n")

	t.Run("parsePEMCertificatesFromPath finds cert in combined file", func(t *testing.T) {
		certs := parsePEMCertificatesFromPath(combinedPEM, "test.combined")
		assert.Len(t, certs, 1)
		assert.Equal(t, "GlobalSign", certs[0].Subject.CommonName)
	})

	t.Run("parsePEMCertificatesFromPath returns nil for non-PEM file", func(t *testing.T) {
		certs := parsePEMCertificatesFromPath([]byte("not a PEM file"), "test.txt")
		assert.Nil(t, certs)
	})

	t.Run("parsePEMCertificatesFromPath returns nil for PEM with only keys", func(t *testing.T) {
		keyOnly := []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBZ2gHaRGWJXjLN6Lxoob\n" +
			"-----END RSA PRIVATE KEY-----\n")
		certs := parsePEMCertificatesFromPath(keyOnly, "test.key")
		assert.Nil(t, certs)
	})
}

func TestIssue56(t *testing.T) {
	t.Run("Issue 56", func(t *testing.T) {
		EcdsaSha256RawCert := []byte("-----BEGIN CERTIFICATE-----\n" +
			"MIIB3DCCAYOgAwIBAgINAgPlfvU/k/2lCSGypjAKBggqhkjOPQQDAjBQMSQwIgYD\n" +
			"VQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjQxEzARBgNVBAoTCkdsb2Jh\n" +
			"bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTIxMTEzMDAwMDAwWhcNMzgw\n" +
			"MTE5MDMxNDA3WjBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0g\n" +
			"UjQxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wWTAT\n" +
			"BgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4xnnTj2wlDp8uORkcA6SumuU5BwkWymOx\n" +
			"uYb4ilfBV85C+nOh92VC/x7BALJucw7/xyHlGKSq2XE/qNS5zowdo0IwQDAOBgNV\n" +
			"HQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUVLB7rUW44kB/\n" +
			"+wpu+74zyTyjhNUwCgYIKoZIzj0EAwIDRwAwRAIgIk90crlgr/HmnKAWBVBfw147\n" +
			"bmF0774BxL4YSFlhgjICICadVGNA3jdgUM/I2O2dgq43mLyjj0xMqTQrbO/7lZsm\n" +
			"-----END CERTIFICATE-----")
		EcdsaSha256Certs, err := parseX509CertFromPath(EcdsaSha256RawCert, "EcdsaSha256Cert.pem")
		if err != nil {
			t.Fail()
		}
		assert.Len(t, EcdsaSha256Certs, 1)
		EcdsaSha256Cert := EcdsaSha256Certs[0]
		assert.Equal(t, EcdsaSha256Cert.SignatureAlgorithm, x509.ECDSAWithSHA256)

		EcdsaSha384RawCert := []byte("-----BEGIN CERTIFICATE-----\n" +
			"MIICHjCCAaSgAwIBAgIRYFlJ4CYuu1X5CneKcflK2GwwCgYIKoZIzj0EAwMwUDEk\n" +
			"MCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpH\n" +
			"bG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTEyMTExMzAwMDAwMFoX\n" +
			"DTM4MDExOTAzMTQwN1owUDEkMCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBD\n" +
			"QSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWdu\n" +
			"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAER0UOlvt9Xb/pOdEh+J8LttV7HpI6SFkc\n" +
			"8GIxLcB6KP4ap1yztsyX50XUWPrRd21DosCHZTQKH3rd6zwzocWdTaRvQZU4f8ke\n" +
			"hOvRnkmSh5SHDDqFSmafnVmTTZdhBoZKo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\n" +
			"VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUPeYpSJvqB8ohREom3m7e0oPQn1kwCgYI\n" +
			"KoZIzj0EAwMDaAAwZQIxAOVpEslu28YxuglB4Zf4+/2a4n0Sye18ZNPLBSWLVtmg\n" +
			"515dTguDnFt2KaAJJiFqYgIwcdK1j1zqO+F4CYWodZI7yFz9SO8NdCKoCOJuxUnO\n" +
			"xwy8p2Fp8fc74SrL+SvzZpA3\n" +
			"-----END CERTIFICATE-----")
		EcdsaSha384Certs, err := parseX509CertFromPath(EcdsaSha384RawCert, "EcdsaSha384Cert.pem")
		if err != nil {
			t.Fail()
		}
		assert.Len(t, EcdsaSha384Certs, 1)
		EcdsaSha384Cert := EcdsaSha384Certs[0]
		assert.Equal(t, EcdsaSha384Cert.SignatureAlgorithm, x509.ECDSAWithSHA384)

		bom := cdx.NewBOM()
		components, dependencyMap, err := x509lib.GenerateCdxComponents(EcdsaSha256Cert)
		if err != nil {
			t.Fail()
		}
		cyclonedx.AddComponents(bom, *components)
		cyclonedx.AddDependencies(bom, *dependencyMap)

		components, dependencyMap, err = x509lib.GenerateCdxComponents(EcdsaSha384Cert)
		if err != nil {
			t.Fail()
		}
		cyclonedx.AddComponents(bom, *components)
		cyclonedx.AddDependencies(bom, *dependencyMap)

		collectedSignatureAlgorithms := make(map[string]bool)
		for _, component := range *bom.Components {
			if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
				assert.Equal(t, component.Name, "GlobalSign")
				signatureAlgorithm := cyclonedx.GetByBomRef(component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef, bom.Components)
				if signatureAlgorithm == nil {
					t.Fail()
				}
				collectedSignatureAlgorithms[signatureAlgorithm.Name] = true
			}
		}

		assert.Len(t, collectedSignatureAlgorithms, 2)
		err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
		if err != nil {
			t.Fail()
		}
	})
}

func TestIssue227_MLDSACertificates(t *testing.T) {
	// The example certificates from RFC 9881, see: https://datatracker.ietf.org/doc/html/rfc9881
	tests := []struct {
		file         string
		name         string
		parameterSet string
		oid          string
		keySize      int
	}{
		{"mldsa44.pem", "ML-DSA-44", "44", "2.16.840.1.101.3.4.3.17", 1312 * 8},
		{"mldsa65.pem", "ML-DSA-65", "65", "2.16.840.1.101.3.4.3.18", 1952 * 8},
		{"mldsa87.pem", "ML-DSA-87", "87", "2.16.840.1.101.3.4.3.19", 2592 * 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join("../../../testdata/mldsa_certificate/dir", test.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			certs, err := parseX509CertFromPath(raw, path)
			if err != nil {
				t.Fatal(err)
			}
			if !assert.Len(t, certs, 1) {
				return
			}

			// The certificate should not be dropped because crypto/x509 does not know the algorithm
			components, dependencyMap, err := x509lib.GenerateCdxComponents(certs[0])
			if err != nil {
				t.Fatal(err)
			}
			bom := cdx.NewBOM()
			cyclonedx.AddComponents(bom, *components)
			cyclonedx.AddDependencies(bom, *dependencyMap)

			foundCertificate := false
			for _, component := range *bom.Components {
				if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
					continue
				}
				foundCertificate = true
				assert.Equal(t, "LAMPS WG", component.Name)

				signatureAlgorithm := cyclonedx.GetByBomRef(component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef, bom.Components)
				if assert.NotNil(t, signatureAlgorithm) {
					assert.Equal(t, test.name, signatureAlgorithm.Name)
					assert.Equal(t, test.oid, signatureAlgorithm.CryptoProperties.OID)
					assert.Equal(t, test.parameterSet, signatureAlgorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
					assert.Equal(t, cdx.CryptoPrimitiveSignature, signatureAlgorithm.CryptoProperties.AlgorithmProperties.Primitive)
				}

				publicKey := cyclonedx.GetByBomRef(component.CryptoProperties.CertificateProperties.SubjectPublicKeyRef, bom.Components)
				if assert.NotNil(t, publicKey) {
					assert.Equal(t, test.name, publicKey.Name)
					assert.Equal(t, test.oid, publicKey.CryptoProperties.OID)
					assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, publicKey.CryptoProperties.RelatedCryptoMaterialProperties.Type)
					assert.Equal(t, test.keySize, *publicKey.CryptoProperties.RelatedCryptoMaterialProperties.Size)

					publicKeyAlgorithm := cyclonedx.GetByBomRef(publicKey.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef, bom.Components)
					if assert.NotNil(t, publicKeyAlgorithm) {
						assert.Equal(t, test.name, publicKeyAlgorithm.Name)
						assert.Equal(t, test.oid, publicKeyAlgorithm.CryptoProperties.OID)
					}
				}
			}
			assert.True(t, foundCertificate)
		})
	}
}
