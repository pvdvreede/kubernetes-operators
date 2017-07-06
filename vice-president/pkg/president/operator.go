package president

import (
	"context"
	"log"
	math_rand "math/rand"
	"sync"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"

	"errors"

	"encoding/base64"
	"io/ioutil"

	"github.com/sapcc/go-vice"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"reflect"
)

const CERTIFICATE_RECHECK_INTERVAL = 5 * time.Second
const CERTIFICATE_VALIDITY_MONTH = 1
const CERTIFICATE_TYPE = "CERTIFICATE"
const PRIVATE_KEY_TYPE = "RSA PRIVATE KEY"
const SECRET_TLS_CERT_TYPE = "tls_cert"
const SECRET_TLS_KEY_TYPE = "tls_key"

var (
	VERSION      = "0.0.0.dev"
	resyncPeriod = 10 * time.Minute
)

type Options struct {
	KubeConfig string

	ViceKeyFile string
	ViceCrtFile string
}

type Operator struct {
	Options

	Clientset       *kubernetes.Clientset
	ViceClient      *vice.Client
	ingressInformer cache.SharedIndexInformer
	secretInformer  cache.SharedIndexInformer

	rootCertPool *x509.CertPool

	queue workqueue.RateLimitingInterface
}

func New(options Options) *Operator {
	config := newClientConfig(options)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Couldn't create Kubernetes client: %s", err)
	}

	if options.ViceCrtFile == "" {
		log.Fatalf("Path to vice certificate not provided. Aborting.")
		return nil
	}
	if options.ViceKeyFile == "" {
		log.Fatalf("Path to vice key not provided. Aborting.")
		return nil
	}
	if options.KubeConfig == "" {
		log.Fatalf("Path to kubeconfig not provided. Aborting.")
		return nil
	}

	cert, err := tls.LoadX509KeyPair(options.ViceCrtFile, options.ViceKeyFile)
	if err != nil {
		log.Fatalf("Couldn't not load certificate from %s and/or key from %s for vice client %s", options.ViceCrtFile, options.ViceKeyFile, err)
	}
	viceClient := vice.New(cert)
	if viceClient == nil {
		log.Fatalf("Couldn't create vice client: %s", err)
	}

	caCert, err := readCertFromFile(options.ViceCrtFile)
	if err != nil {
		log.Fatalf("Couldn't read CA Cert")
	}
	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(caCert)

	operator := &Operator{
		Options:      options,
		Clientset:    clientset,
		ViceClient:   viceClient,
		rootCertPool: rootCertPool,
		queue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	ingressInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
				return clientset.Ingresses(v1.NamespaceAll).List(meta_v1.ListOptions{})
			},
			WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
				return clientset.Ingresses(v1.NamespaceAll).Watch(meta_v1.ListOptions{})
			},
		},
		&v1beta1.Ingress{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	secretInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
				return clientset.Secrets(v1.NamespaceAll).List(meta_v1.ListOptions{})
			},
			WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
				return clientset.Secrets(v1.NamespaceAll).Watch(meta_v1.ListOptions{})
			},
		},
		&v1.Secret{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	ingressInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    operator.ingressAdd,
		UpdateFunc: operator.ingressUpdate,
		DeleteFunc: operator.ingressDelete,
	})

	operator.ingressInformer = ingressInformer
	operator.secretInformer = secretInformer

	return operator
}

func newClientConfig(options Options) *rest.Config {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}

	if options.KubeConfig != "" {
		rules.ExplicitPath = options.KubeConfig
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		log.Fatalf("Couldn't get Kubernetes default config: %s", err)
	}

	return config
}

func (vp *Operator) Run(threadiness int, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer vp.queue.ShutDown()
	defer wg.Done()
	wg.Add(1)

	log.Printf("Ladies and Gentlemen, the Vice President! Renewing your Symantec certificates now in version %v\n", VERSION)

	go vp.ingressInformer.Run(stopCh)

	log.Printf("Waiting for cache to sync...")
	cache.WaitForCacheSync(stopCh, vp.ingressInformer.HasSynced)
	log.Printf("Cache primed. Ready for operations.")

	for i := 0; i < threadiness; i++ {
		go wait.Until(vp.runWorker, time.Second, stopCh)
	}

	ticker := time.NewTicker(CERTIFICATE_RECHECK_INTERVAL)
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Printf("Next check in %v", CERTIFICATE_RECHECK_INTERVAL)
				vp.checkCertificates()
			case <-stopCh:
				ticker.Stop()
				return
			}
		}
	}()

	<-stopCh
}

func (vp *Operator) runWorker() {
	for vp.processNextWorkItem() {
	}
}

func (vp *Operator) processNextWorkItem() bool {
	key, quit := vp.queue.Get()
	if quit {
		return false
	}
	defer vp.queue.Done(key)

	// do your work on the key.  This method will contains your "do stuff" logic
	err := vp.syncHandler(key)
	if err == nil {
		vp.queue.Forget(key)
		return true
	}

	log.Printf("%v failed with : %v", key, err)
	vp.queue.AddRateLimited(key)

	return true
}

func (vp *Operator) syncHandler(key interface{}) error {
	o, exists, err := vp.ingressInformer.GetStore().Get(key)
	if err != nil {
		return err
	}

	if !exists {
		return nil
	}

	ingress := o.(*v1beta1.Ingress)
	for _, tls := range ingress.Spec.TLS {

		log.Printf("Checking Ingress %v/%v: Hosts: %v, Secret: %v/%v", ingress.Namespace, ingress.Name, tls.Hosts, ingress.Namespace, tls.SecretName)

		random := math_rand.Intn(640) + 1
		time.Sleep(time.Duration(random) * time.Millisecond)

		for _, host := range tls.Hosts {

			var err error

			// does the secret exist?
			secret, err := vp.GetSecret(ingress.Namespace, tls.SecretName)
			if err != nil {
				log.Printf("Couldn't get secret for ingress %s/%s and host %s. Creating new secret and certificate.", ingress.Namespace, ingress.Name, host)
				_, err := vp.EnrollCertificateAndUpdateSecret(secret, tls.Hosts)
				// TODO: update secret
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.", ingress.Namespace, ingress.Name, host)
					return err
				}
				return nil
			}

			// does the certificate exists? can it be decoded and parsed?
			//TODO: multiple certs: for _, cert := range secret.Data[SECRET_TLS_CERT_TYPE] {}
			cert, key, err := vp.GetCertificateAndKeyFromSecret(secret)
			if err != nil {
				log.Printf("Couldn't get certificate from secret %s for ingress %s/%s ,host %s. Enrolling new one.", secret.Name, ingress.Namespace, ingress.Name, host)
				_, err := vp.EnrollCertificateAndUpdateSecret(secret, tls.Hosts)
				// TODO: update secret
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.", ingress.Namespace, ingress.Name, host)
					return err
				}
				return nil
			}

			// does the secret contain the correct key for the certificate?
			if !vp.DoesKeyAndCertificateTally(cert, key) {
				log.Printf("Certificate and Key don't match secret %s of ingress %s/%s and host %s .", secret.Name, ingress.Namespace, ingress.Name, host)
				_, err := vp.RenewCertificateAndUpdateSecret(secret, cert, host)
				//TODO: update secret
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.", ingress.Namespace, ingress.Name, host)
					return err
				}
				return errors.New("Certificate and Key don't match.")
			}

			//  is the certificate for the correct host?
			if !vp.DoesCertificateAndHostMatch(cert, host) {
				log.Printf("Certificate reports wrong host. Enrolling new certificate for %s.", host)
				_, err := vp.EnrollCertificateAndUpdateSecret(secret, []string{host})
				//TODO: update secret
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.", ingress.Namespace, ingress.Name, host)
					return err
				}
				return nil
			}

			// is the certificate valid for time t ?
			if vp.DoesCertificateExpireSoon(cert) {
				log.Printf("Certificate for host %s will expire in %s month. Renewing", host, CERTIFICATE_VALIDITY_MONTH)
				_, err := vp.RenewCertificateAndUpdateSecret(secret, cert, host)
				//TODO: update secret
				if err != nil {
					log.Printf("Couldn't renew certificate for ingress %s/%s and host %s.", ingress.Namespace, ingress.Name, host)
					return err
				}
			}
		}
	}
	return nil
}

func (vp *Operator) enrollCertificate(sans []string) (newCert *x509.Certificate, key *rsa.PrivateKey, err error) {

	csr, key, err := vp.createCSR()
	if err != nil {
		log.Printf("Couldn't enroll new certificate %s", err.Error())
		return nil, nil, err
	}

	enrollment, err := vp.ViceClient.Certificates.Enroll(
		context.TODO(),
		&vice.EnrollRequest{
			FirstName:          "Michael",
			LastName:           "Schmidt",
			Email:              "michael.schmidt@email.com",
			CSR:                string(csr),
			SubjectAltNames:    sans,
			Challenge:          "Passwort1!",
			CertProductType:    vice.CertProductType.Server,
			ServerType:         vice.ServerType.OpenSSL,
			ValidityPeriod:     vice.ValidityPeriod.OneYear,
			SignatureAlgorithm: vice.SignatureAlgorithm.SHA256WithRSAEncryption,
		},
	)

	if err != nil {
		log.Printf("Couldn't enroll new certificate %s", err.Error())
		return nil, nil, err
	}

	newCert, err = x509.ParseCertificate([]byte(enrollment.Certificate))
	if err != nil {
		log.Printf("Couldn't parse certificate: %s", err)
		return nil, nil, err
	}
	return newCert, key, nil
}

func (vp *Operator) EnrollCertificateAndUpdateSecret(oldSecret *v1.Secret, sans []string) (updatedSecret *v1.Secret, err error) {

	cert, key, err := vp.enrollCertificate(sans)
	if err != nil {
		log.Printf("Couldn't enroll certificate for secret %s/%s", oldSecret.Namespace, oldSecret.Name)
		return nil, err
	}

	updatedSecret, err = vp.addCertificateAndKeyToSecret(cert, key, oldSecret)
	if err != nil {
		log.Printf("Couldn't update secret %s/%s: %s", oldSecret.Namespace, oldSecret.Name, err)
		return nil, err
	}
	return updatedSecret, nil
}

func (vp *Operator) RenewCertificateAndUpdateSecret(oldSecret *v1.Secret, oldCert *x509.Certificate, host string) (updatedSecret *v1.Secret, err error) {

	newCert, key, err := vp.renewCertificate(oldCert)
	if err != nil {
		return nil, err
	}

	updatedSecret, err = vp.addCertificateAndKeyToSecret(newCert, key, oldSecret)
	if err != nil {
		return nil, err
	}
	return updatedSecret, nil
}

func (vp *Operator) renewCertificate(oldCert *x509.Certificate) (newCert *x509.Certificate, key *rsa.PrivateKey, err error) {

	csr, key, err := vp.createCSR()
	if err != nil {
		log.Printf("Couldn't renew certificate %s", err.Error())
		return nil, nil, err
	}

	renewal, err := vp.ViceClient.Certificates.Renew(
		context.TODO(),
		&vice.RenewRequest{
			FirstName:           oldCert.Issuer.CommonName,
			LastName:            "Schmidt",
			Email:               "michael.schmidt@email.com",
			CSR:                 string(csr),
			SubjectAltNames:     oldCert.DNSNames,
			OriginalCertificate: string(oldCert.Raw),
			OriginalChallenge:   "Passwort1!",
			Challenge:           "Passwort2!",
			CertProductType:     vice.CertProductType.Server,
			ServerType:          vice.ServerType.OpenSSL,
			ValidityPeriod:      vice.ValidityPeriod.OneYear,
			SignatureAlgorithm:  vice.SignatureAlgorithm.SHA256WithRSAEncryption,
		},
	)
	if err != nil {
		log.Printf("Couldn't renew certificate: %s.", err)
		return nil, nil, err
	}
	newCert, err = x509.ParseCertificate([]byte(renewal.Certificate))
	if err != nil {
		log.Printf("Couldn't parse certificate: %s", err)
		return nil, nil, err
	}
	return newCert, key, nil
}

func (vp *Operator) DoesCertificateAndHostMatch(cert *x509.Certificate, host string) bool {
	if _, err := cert.Verify(
		x509.VerifyOptions{
			DNSName: host,
		}); err != nil {
		log.Printf("failed to verify certificate for host %s: %s", host, err.Error())
		return false
	}
	return true
}

// already expired? or will the certificate expire within the next n month?
func (vp *Operator) DoesCertificateExpireSoon(cert *x509.Certificate) bool {
	return !cert.NotAfter.UTC().After(time.Now().UTC().AddDate(0, CERTIFICATE_VALIDITY_MONTH, 0))
}

func (vp *Operator) DoesKeyAndCertificateTally(cert *x509.Certificate, key *rsa.PrivateKey) bool {

	certBlock := pem.Block{
		Type:  CERTIFICATE_TYPE,
		Bytes: cert.Raw,
	}

	keyBlock := pem.Block{
		Type:  PRIVATE_KEY_TYPE,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if _, err := tls.X509KeyPair(pem.EncodeToMemory(&certBlock), pem.EncodeToMemory(&keyBlock)); err != nil {
		log.Printf("Certificate and Key don't match: %s", err)
		return false
	}
	return true
}

func (vp *Operator) updateSecret(namespace string, secret *v1.Secret) (result *v1.Secret, err error) {
	return vp.Clientset.Secrets(namespace).Update(secret)
}

// get secret by namespace and name
func (vp *Operator) GetSecret(namespace string, secretName string) (*v1.Secret, error) {
	return vp.Clientset.Secrets(namespace).Get(secretName, meta_v1.GetOptions{})
}

func (vp *Operator) GetCertificateAndKeyFromSecret(secret *v1.Secret) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	for k, v := range secret.Data {
		switch k {
		case SECRET_TLS_CERT_TYPE:
			decodedCert := make([]byte, base64.StdEncoding.DecodedLen(len(v)))
			l, err := base64.StdEncoding.Decode(decodedCert, v)
			if err != nil {
				log.Printf("Couldn't decode base64 certificate: %s", err.Error())
				break
			}
			cert, err = vp.readCertificateFromPEM(decodedCert[:l])
		case SECRET_TLS_KEY_TYPE:
			decodedKey := make([]byte, base64.StdEncoding.DecodedLen(len(v)))
			l, err := base64.StdEncoding.Decode(decodedKey, v)
			if err != nil {
				log.Printf("Couldn't decode base64 private key: %s", err.Error())
				break
			}
			key, err = vp.readPrivateKeyFromPEM(decodedKey[:l])
		}

	}
	if err != nil {
		log.Printf(err.Error())
		return nil, nil, err
	}
	if cert == nil && key == nil {
		log.Printf("Neither certificate nor private key found in secret: %s", secret.Name)
		return nil, nil, err
	}
	return cert, key, nil
}

func (vp *Operator) addCertificateAndKeyToSecret(cert *x509.Certificate, key *rsa.PrivateKey, oldSecret *v1.Secret) (secret *v1.Secret, err error) {

	certPEM, err := vp.writeCertificateToPEM(cert)
	if err != nil {
		log.Printf("Couldn't export certificate to PEM: %s", err)
		return nil, err
	}
	keyPEM, err := vp.writePrivateKeyToPEM(key)
	if err != nil {
		log.Printf("Couldn't export key to PEM: %s", err)
		return nil, err
	}

	encodedCert, err := vp.base64EncodePEM(certPEM)
	if err != nil {
		return nil, err
	}

	encodedKey, err := vp.base64EncodePEM(keyPEM)
	if err != nil {
		return nil, err
	}

	return &v1.Secret{
		Type:       oldSecret.Type,
		TypeMeta:   oldSecret.TypeMeta,
		ObjectMeta: oldSecret.ObjectMeta,
		Data: map[string][]byte{
			SECRET_TLS_CERT_TYPE: encodedCert,
			SECRET_TLS_KEY_TYPE:  encodedKey,
		},
	}, nil
}

func (vp *Operator) createCSR() (csr []byte, key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Couldn't generate private key: %s", err)
		return nil, nil, err
	}

	csr, err = vice.CreateCSR(
		pkix.Name{
			CommonName:         "vice.sap.com",
			Country:            []string{"DE"},
			Province:           []string{"BERLIN"},
			Locality:           []string{"BERLIN"},
			Organization:       []string{"SAP SE"},
			OrganizationalUnit: []string{"Infrastructure Automation"},
		},
		"michael02.schmidt@sap.com",
		[]string{"vice.sap.com", "certificates.sap.com"},
		key,
	)
	if err != nil {
		log.Printf("Couldn't create CSR: %s", err)
		return nil, nil, err
	}

	return csr, key, nil
}

func (vp *Operator) base64EncodePEM(pem []byte) (base64EncodedPEM []byte, err error) {
	base64EncodedPEM = make([]byte, base64.StdEncoding.DecodedLen(len(pem)))
	base64.StdEncoding.Encode(base64EncodedPEM, pem)
	if base64EncodedPEM == nil {
		return nil, errors.New("Couldn't base64-encode certificate")
	}
	return base64EncodedPEM, nil
}

func (vp *Operator) readPrivateKeyFromPEM(keyPEM []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the public key")
	}
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Could not parse private key: %s", err.Error())
		return nil, err
	}
	return key, nil
}

func (vp *Operator) writePrivateKeyToPEM(key *rsa.PrivateKey) (keyPEM []byte, err error) {
	keyPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  PRIVATE_KEY_TYPE,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	if keyPEM == nil {
		return nil, errors.New("Couldn't encode private key to PEM.")
	}
	return keyPEM, nil
}

func (vp *Operator) readCertificateFromPEM(certPEM []byte) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate.")
	}
	if block.Type != CERTIFICATE_TYPE {
		return nil, errors.New("certificate contains invalid data")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("failed to parse certificate: %s", err.Error())
		return nil, err
	}
	return cert, nil
}

func (vp *Operator) writeCertificateToPEM(cert *x509.Certificate) (certPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  CERTIFICATE_TYPE,
			Bytes: cert.Raw,
		},
	)
	if certPEM == nil {
		return nil, errors.New("Couldn't encode certificate.")
	}
	return certPEM, nil
}

func (vp *Operator) ingressAdd(obj interface{}) {
	i := obj.(*v1beta1.Ingress)
	vp.queue.Add(i)
}

func (vp *Operator) ingressDelete(obj interface{}) {
	i := obj.(*v1beta1.Ingress)
	err := vp.Clientset.Ingresses(i.Namespace).Delete(i.Name, &meta_v1.DeleteOptions{})
	if err != nil {
		log.Printf("Could not delete ingress %s/%s.", i.Namespace, i.Name)
		return
	}
	//key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(i)
	//if err == nil {
	//	vp.queue.Add(key)
	//}
	vp.queue.Add(i)
	log.Printf("Deleted ingress %s/%s.", i.Namespace, i.Name)

}

func (vp *Operator) ingressUpdate(cur, old interface{}) {
	iOld := old.(*v1beta1.Ingress)
	iCur := cur.(*v1beta1.Ingress)

	if !reflect.DeepEqual(iOld.Spec,iCur.Spec) {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(iCur)
	if err != nil {
		return
	}
	vp.queue.Add(key)
	log.Printf("Updated ingress %s/%s",iCur.Namespace,iCur.Name)
}

func (vp *Operator) checkCertificates() {
	for _, o := range vp.ingressInformer.GetStore().List() {
		ingress := o.(*v1beta1.Ingress)
		vp.queue.Add(ingress)
	}
}

func (vp *Operator) secretAdd(obj interface{}) {
	s := obj.(*v1.Secret)
	vp.queue.Add(s)
}

func readCertFromFile(filePath string) (cert *x509.Certificate, err error) {
	certPEM, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("Couldn't read file. %s", err)
		return nil, err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Printf("Failed to parse certificate PEM.")
		return nil, errors.New("Failed to parse certificate PEM.")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Couldn't parse certificate. %s", err)
		return nil, err
	}
	return cert, nil
}

func readKeyFromFile(filePath string) (key *rsa.PrivateKey, err error) {
	keyRaw, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("Couldn't read file. %s", err)
		return nil, err
	}
	key, err = x509.ParsePKCS1PrivateKey(keyRaw)
	if err != nil {
		log.Printf("Couldn't parse key. %s", err)
		return nil, err
	}
	return key, nil
}
