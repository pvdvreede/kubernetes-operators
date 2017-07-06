package tests

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"fmt"
	"os"

	"github.com/sapcc/kubernetes-operators/vice-president/pkg/president"
	"github.com/stretchr/testify/suite"
	"strconv"
)

const FIXTURES = "fixtures"
const TESTPORT = 8001

type TestSuite struct {
	suite.Suite
	VP          *president.Operator
	HttpMux     *http.ServeMux
	TestPort    int
	Cert        *x509.Certificate
	CertByte    []byte
	NewCert     *x509.Certificate
	NewCertByte []byte
	Key         *rsa.PrivateKey
	KeyByte     []byte
}

func (s *TestSuite) SetupSuite() {
	s.T().Logf("Initializing TestSuite")
	testPort := strconv.Itoa(TESTPORT)
	var err error

	//read cert from fixtures
	s.CertByte, err = s.readFixture("example.pem")
	if err != nil {
		log.Printf("Couldn't read example.pem")
	}
	certBlock, _ := pem.Decode(s.CertByte)
	if certBlock == nil {
		s.T().Errorf("failed to decode PEM block containing certificate.")
	}
	s.Cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		s.T().Errorf("failed to parse certificate: %s", err.Error())
	}

	//read new cert from fixtures
	s.NewCertByte, err = s.readFixture("newExample.pem")
	if err != nil {
		log.Printf("Couldn't read newExample.pem")
	}
	newCertBlock, _ := pem.Decode(s.NewCertByte)
	if newCertBlock == nil {
		s.T().Errorf("failed to decode PEM block containing certificate.")
	}
	s.NewCert, err = x509.ParseCertificate(newCertBlock.Bytes)
	if err != nil {
		s.T().Errorf("failed to parse certificate: %s", err.Error())
	}

	//read private key from fixtures
	s.KeyByte, err = s.readFixture("example.key")
	if err != nil {
		log.Printf("Couldn't read example.key")
	}
	keyBlock, _ := pem.Decode(s.KeyByte)
	if keyBlock == nil {
		s.T().Errorf("Failed to decode PEM block containing the public key")
	}
	s.Key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		s.T().Errorf("Could not parse private key: %s", err.Error())
	}

	//create vice president
	s.VP = president.New(president.Options{
		ViceCrtFile: "fixtures/example.pem",
		ViceKeyFile: "fixtures/example.key",
		KubeConfig:  "fixtures/example.kubeconfig",
	})

	s.VP.ViceClient.BaseURL, _ = url.Parse(fmt.Sprintf("http://localhost:%s", testPort))

	go s.setupMockServer(testPort)
	time.Sleep(2 * time.Second)
}

func (s *TestSuite) TearDownSuite() {
	s.T().Logf("Shutting down TestSuite.")
}

func (s *TestSuite) setupMockServer(port string) {
	s.T().Logf("Starting local mockserver on port %s.", port)
	s.HttpMux = http.NewServeMux()

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), s.HttpMux)
	s.T().Errorf(err.Error())
}

func (s *TestSuite) readFixture(fileName string) (file []byte, err error) {
	pwd, err := os.Getwd()
	if err != nil {
		s.T().Errorf("Couldn't get current path. %s", err)
		return nil, err
	}
	fullPath := path.Join(pwd, FIXTURES, fileName)
	file, err = ioutil.ReadFile(fullPath)
	if err != nil {
		s.T().Errorf("Couldn't load file %s. %s", fullPath, err)
		return nil, err
	}
	return file, nil
}

func (s *TestSuite) respondWith(endpoint string, responseCode int, jsonPath string) {

	json, _ := s.readFixture(jsonPath)

	s.HttpMux.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(responseCode)
		w.Header().Set("Content-Type", "application/json, */*")
		w.Header().Set("Encoding", "gzip")
		w.Write(json)
	})
}
