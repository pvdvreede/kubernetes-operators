package president

import (
	"context"
	"log"
	"math/rand"
	"sync"
	"time"

	"crypto/x509"
	"encoding/pem"

	"crypto/rsa"
	"crypto/tls"

	"errors"

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
)

const CERTIFICATE_RECHECK_INTERVAL = 5 * time.Second
const CERTIFICATE_VALIDITY_MONTH = 1

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

	clientset       *kubernetes.Clientset
	viceClient      *vice.Client
	ingressInformer cache.SharedIndexInformer
	secretInformer  cache.SharedIndexInformer

	queue workqueue.RateLimitingInterface
}

func New(options Options) *Operator {
	config := newClientConfig(options)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Couldn't create Kubernetes client: %s", err)
	}

	cert, err := tls.LoadX509KeyPair(options.ViceCrtFile, options.ViceKeyFile)
	if err != nil {
		log.Fatalf("Couldn't not load certificate and/or key for vice client: %s", err)
	}
	viceClient := vice.New(cert)
	if viceClient == nil {
		log.Fatalf("Couldn't create vice client: %s", err)
	}

	operator := &Operator{
		Options:    options,
		clientset:  clientset,
		viceClient: viceClient,
		queue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
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

		random := rand.Intn(640) + 1
		time.Sleep(time.Duration(random) * time.Millisecond)

		for _,host := range tls.Hosts {

			var err error

			// does the secret exist?
			secret, err := vp.getSecret(ingress.Namespace, tls.SecretName)
			if err != nil {
				log.Printf("Couldn't get secret for ingress %s/%s and host %s. Enrolling new one.",ingress.Namespace,ingress.Name,host)
				cert, err := vp.enrollCertificate()
				log.Printf(string(cert.Raw)) //TODO: update secret and ingress
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.",ingress.Namespace,ingress.Name,host)
					return err
				}
				return nil
			}

			// does the certificate exists? can it be decoded and parsed?
			cert, key, err := vp.getCertificateFromSecret(secret)
			if err != nil {
				log.Printf("Couldn't get certificate from secret %s for ingress %s/%s ,host %s. Enrolling new one.",secret.Name,ingress.Namespace,ingress.Name,host)
				cert, err := vp.enrollCertificate()
				log.Printf(string(cert.Raw)) //TODO: update secret and ingress
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.",ingress.Namespace,ingress.Name,host)
					return err
				}
				return nil
			}

			// does the secret contain the correct key for the certificate?
			if !vp.doesKeyAndCertificateTally(cert, key) {
				log.Printf("Certificate and Key don't match secret %s of ingress %s/%s and host %s .",secret.Name,ingress.Namespace,ingress.Name,host)
				cert, err := vp.enrollCertificate()
				log.Printf(string(cert.Raw)) //TODO: update secret and ingress
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.",ingress.Namespace,ingress.Name,host)
					return err
				}
				return errors.New("Certificate and Key don't match.")
			}

			//  is the certificate for the correct host?
			if !vp.doesCertificateAndHostMatch(cert,host) {
				log.Printf("Certificate reports wrong host. Enrolling new certificate for %s.",host)
				cert, err := vp.enrollCertificate()
				log.Printf(string(cert.Raw)) //TODO: update secret and ingress
				if err != nil {
					log.Printf("Couldn't enroll new certificate for ingress %s/%s and host %s.",ingress.Namespace,ingress.Name,host)
					return err
				}
				return nil
			}

			// is the certificate valid for time t ?
			if vp.doesCertificateExpireSoon(cert) {
				log.Printf("Certificate for host %s will expire in %s month. Renewing",host,CERTIFICATE_VALIDITY_MONTH)
				cert, err := vp.renewCertificate(cert)
				log.Printf(string(cert.Raw)) //TODO: update secret and ingress
				if err != nil {
					log.Printf("Couldn't renew certificate for ingress %s/%s and host %s.",ingress.Namespace,ingress.Name,host)
					return err
				}
			}

			return nil
		}
	}
	return nil
}

func (vp *Operator) enrollCertificate() (newCert *x509.Certificate, err error) {
	enrollment, err := vp.viceClient.Certificates.Enroll(
		context.TODO(),
		&vice.EnrollRequest{
			FirstName:           "Michael",
			LastName:            "Schmidt",
			Email:               "michael.schmidt@email.com",
			CSR:                 string("CSR"),
			SubjectAltNames:     []string{},
			Challenge:           "Passwort1!",
			CertProductType:     vice.CertProductType.Server,
			ServerType:          vice.ServerType.OpenSSL,
			ValidityPeriod:      vice.ValidityPeriod.OneYear,
			SignatureAlgorithm:  vice.SignatureAlgorithm.SHA256WithRSAEncryption,
		},
	)

	if err != nil {
		log.Printf("Couldn't enroll new certificate %s",err.Error())
		return nil, err
	}

	newCert,err = x509.ParseCertificate([]byte( enrollment.Certificate))
	if err != nil {
		log.Printf("Couldn't parse certificate: %s",err)
		return nil,err
	}
	return newCert,nil
}


func (vp *Operator) renewCertificate(oldCert *x509.Certificate) (newCert *x509.Certificate, err error) {
	renewal, err := vp.viceClient.Certificates.Renew(
		context.TODO(),
		&vice.RenewRequest{
			FirstName:           oldCert.Issuer.CommonName,
			LastName:            "Schmidt",
			Email:               "michael.schmidt@email.com",
			CSR:                 "CSR",
			SubjectAltNames:     oldCert.DNSNames,  //TODO: oldCert.Extensions
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
		log.Printf("Couldn't renew certificate: %s.",err)
		return nil,err
	}
	newCert,err = x509.ParseCertificate([]byte(renewal.Certificate))
	if err != nil {
		log.Printf("Couldn't parse certificate: %s",err)
		return nil,err
	}
	return newCert,nil
}

func (vp *Operator) doesCertificateAndHostMatch(cert *x509.Certificate, host string) bool {

	//TODO: verify cert
	/*opts := x509.VerifyOptions{
		DNSName: "mail.google.com",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}*/

	return true
}

// already expired or will the certificate expire within the next n month
func (vp *Operator) doesCertificateExpireSoon(cert *x509.Certificate) bool {
	return cert.NotAfter.UTC().After(time.Now().UTC().AddDate(0, CERTIFICATE_VALIDITY_MONTH, 0))
}

func (vp *Operator) doesKeyAndCertificateTally(cert *x509.Certificate, key *rsa.PrivateKey) bool {

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte(cert),
	}

	keyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte(key),
	}

	if _, err := tls.X509KeyPair(pem.EncodeToMemory(&certBlock), pem.EncodeToMemory(&keyBlock)); err != nil {
		log.Printf("Certificate and Key don't match: %s", err)
		return false
	}
	return true
}

// get secret by namespace and name
func (vp *Operator) getSecret(namespace string, secretName string) (*v1.Secret, error) {
	return vp.clientset.Secrets(namespace).Get(secretName, meta_v1.GetOptions{})
}

func (vp *Operator) getCertificateFromSecret(secret *v1.Secret) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {

	for k, v := range secret.StringData {
		switch k {
		case "tls.cert":
			cert, err = vp.getCertificateFromPEM(v)
		case "tls.key":
			key, err = vp.getPrivateKeyFromPEM(v)
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

func (vp *Operator) getPrivateKeyFromPEM(keyPEM string) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(keyPEM))
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

func (vp *Operator) getCertificateFromPEM(certPEM string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate.")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate contains invalid data")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("failed to parse certificate: %s", err.Error())
		return nil, err
	}
	return cert, nil
}

func (vp *Operator) ingressAdd(obj interface{}) {
	i := obj.(*v1beta1.Ingress)
	vp.queue.Add(i)
}

func (vp *Operator) ingressDelete(obj interface{}) {
	i := obj.(*v1beta1.Ingress)
	//err := vp.clientset.Ingresses(i.Namespace).Delete(i.Name,&meta_v1.DeleteOptions{})
	//if err != nil {
	//	log.Printf("Could not delete ingress %s in namespace .",i.Name,i.Namespace)
	//}
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(i)
	if err == nil {
		vp.queue.Add(key)
	}
}

func (vp *Operator) ingressUpdate(cur, old interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(cur)
	if err == nil {
		vp.queue.Add(key)
	}
}

func (vp *Operator) checkCertificates() {
	for _, o := range vp.ingressInformer.GetStore().List() {
		ingress := o.(*v1beta1.Ingress)
		vp.queue.Add(ingress)
	}
}
