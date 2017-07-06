package tests

import (
	"encoding/base64"
	"testing"

	"crypto/rand"
	"crypto/rsa"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
)

const NAMESPACE = "default"
const SECRETNAME = "my-secret"

func TestMySuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (s *TestSuite) TestGetSecret() {

	s.respondWith("/api/v1/namespaces/default/secrets/my-secret", 200, "mySecret.json")

	secretExpected := &v1.Secret{
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls_cert": s.CertByte,
			"tls_key":  s.KeyByte,
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: NAMESPACE,
			Name:      SECRETNAME,
		},
	}

	secretActual, err := s.VP.GetSecret(NAMESPACE, SECRETNAME)
	if err != nil {
		s.T().Errorf("Couldn't get secret: %s", err.Error())
	}
	assert.Equal(s.T(), secretExpected.Name, secretActual.Name)

	for k, v := range secretActual.StringData {
		assert.Equal(s.T(), secretExpected.StringData[k], v)
	}
}

func (s *TestSuite) TestGetCertificateFromSecret() {

	secret := &v1.Secret{
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls_cert": []byte(base64.StdEncoding.EncodeToString(s.CertByte)),
			"tls_key":  []byte(base64.StdEncoding.EncodeToString(s.KeyByte)),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: NAMESPACE,
			Name:      SECRETNAME,
		},
	}

	cert, key, err := s.VP.GetCertificateAndKeyFromSecret(secret)
	if err != nil {
		s.T().Errorf("Couldn't get certificate from secret: %s", err.Error())
	}

	assert.Equal(s.T(), s.Cert, cert)
	assert.Equal(s.T(), s.Key, key)

}

func (s *TestSuite) TestCertificateAndHostMatch() {

	assert.False(s.T(), s.VP.DoesCertificateAndHostMatch(s.Cert, "example.com"))
	assert.False(s.T(), s.VP.DoesCertificateAndHostMatch(s.Cert, "invalid.com"))

}

func (s *TestSuite) TestDoesKeyAndCertificateTally() {

	randomKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.T().Errorf("Couldn't generate random key. %s", err.Error())
	}

	assert.True(s.T(), s.VP.DoesKeyAndCertificateTally(s.Cert, s.Key))
	assert.False(s.T(), s.VP.DoesKeyAndCertificateTally(s.Cert, randomKey))

}

func (s *TestSuite) TestDoesCertificateExpireSoon() {

	assert.False(s.T(), s.VP.DoesCertificateExpireSoon(s.Cert))

}

//func (s *TestSuite) TestRenewCertificateAndUpdateSecret() {
//
//	s.respondWith("/vswebservices/rest/services/renew", 200, "newExample.pem")
//
//	oldSecret := &v1.Secret{
//		Type: v1.SecretTypeOpaque,
//		Data: map[string][]byte{
//			"tls_cert": []byte(base64.StdEncoding.EncodeToString(s.CertByte)),
//			"tls_key":  []byte(base64.StdEncoding.EncodeToString(s.KeyByte)),
//		},
//		ObjectMeta: meta_v1.ObjectMeta{
//			Namespace: NAMESPACE,
//			Name:      SECRETNAME,
//		},
//	}
//
//	updatedSecretExpected := &v1.Secret{
//		Type: v1.SecretTypeOpaque,
//		Data: map[string][]byte{
//			"tls_cert": []byte(base64.StdEncoding.EncodeToString(s.CertByte)),
//			"tls_key":  []byte(base64.StdEncoding.EncodeToString(s.KeyByte)),
//		},
//		ObjectMeta: meta_v1.ObjectMeta{
//			Namespace: NAMESPACE,
//			Name:      SECRETNAME,
//		},
//	}
//
//	host := "example.com"
//
//	updatedSecretActual, err := s.VP.RenewCertificateAndUpdateSecret(oldSecret, s.Cert, host)
//	if err != nil {
//		s.T().Errorf(err.Error())
//	}
//
//	for k, v := range updatedSecretActual.Data {
//		log.Printf(k, ":", string(v))
//	}
//
//	assert.Equal(s.T(), updatedSecretExpected.Data, updatedSecretActual.Data)
//}
