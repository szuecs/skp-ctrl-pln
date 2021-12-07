package fabric

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/predicates"
	"github.com/zalando/skipper/secrets"
)

const (
	IngressesV1ClusterURI      = "/apis/networking.k8s.io/v1/ingresses"
	ServicesClusterURI         = "/api/v1/services"
	EndpointsClusterURI        = "/api/v1/endpoints"
	ZalandoResourcesClusterURI = "/apis/zalando.org/v1"
	FabricGatewayName          = "fabricgateways"
	FabricGatewayURI           = ZalandoResourcesClusterURI + "/fabricgateways"
	FabricGatewayFmt           = ZalandoResourcesClusterURI + "/namespaces/%s/fabricgateways"
	defaultKubernetesURL       = "http://localhost:8001"
	serviceHostEnvVar          = "KUBERNETES_SERVICE_HOST"
	servicePortEnvVar          = "KUBERNETES_SERVICE_PORT"
	serviceAccountDir          = "/var/run/secrets/kubernetes.io/serviceaccount/"
	serviceAccountTokenKey     = "token"
	serviceAccountRootCAKey    = "ca.crt"
)

var (
	errResourceNotFound     = errors.New("resource not found")
	errServiceNotFound      = errors.New("service not found")
	errAPIServerURLNotFound = errors.New("kubernetes API server URL could not be constructed from env vars")
	errInvalidCertificate   = errors.New("invalid CA")

	nonWord = regexp.MustCompile(`\W`)
)

type clusterClient struct {
	fabricURI     string
	servicesURI   string
	endpointsURI  string
	tokenProvider secrets.SecretsProvider
	httpClient    *http.Client
	apiURL        string

	loggedMissingRouteGroups bool
}

type FabricDataClient struct {
	quit          chan struct{}
	ClusterClient *clusterClient
	testIn        string
	testOut       string
}

type Options struct {
	KubernetesURL       string
	KubernetesInCluster bool
}

func buildAPIURL(o Options) (string, error) {
	if !o.KubernetesInCluster {
		if o.KubernetesURL == "" {
			return defaultKubernetesURL, nil
		}
		return o.KubernetesURL, nil
	}

	host, port := os.Getenv(serviceHostEnvVar), os.Getenv(servicePortEnvVar)
	if host == "" || port == "" {
		return "", errAPIServerURLNotFound
	}

	return "https://" + net.JoinHostPort(host, port), nil
}

func buildHTTPClient(certFilePath string, inCluster bool, quit <-chan struct{}) (*http.Client, error) {
	if !inCluster {
		return http.DefaultClient, nil
	}

	rootCA, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(rootCA) {
		return nil, errInvalidCertificate
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 30 * time.Second,
		MaxIdleConns:          5,
		MaxIdleConnsPerHost:   5,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
		},
	}

	// regularly force closing idle connections
	go func() {
		for {
			select {
			case <-time.After(10 * time.Second):
				transport.CloseIdleConnections()
			case <-quit:
				return
			}
		}
	}()

	return &http.Client{
		Transport: transport,
	}, nil
}

func newClusterClient(o Options, apiURL string, quit <-chan struct{}) (*clusterClient, error) {
	httpClient, err := buildHTTPClient(serviceAccountDir+serviceAccountRootCAKey, o.KubernetesInCluster, quit)
	if err != nil {
		return nil, err
	}

	c := &clusterClient{
		fabricURI:    FabricGatewayURI,
		servicesURI:  ServicesClusterURI,
		endpointsURI: EndpointsClusterURI,
		httpClient:   httpClient,
		apiURL:       apiURL,
	}

	if o.KubernetesInCluster {
		c.tokenProvider = secrets.NewSecretPaths(time.Minute)
		err := c.tokenProvider.Add(serviceAccountDir + serviceAccountTokenKey)
		if err != nil {
			log.Errorf("Failed to Add secret %s: %v", serviceAccountDir+serviceAccountTokenKey, err)
			return nil, err
		}

		b, ok := c.tokenProvider.GetSecret(serviceAccountDir + serviceAccountTokenKey)
		if !ok {
			return nil, fmt.Errorf("failed to GetSecret: %s", serviceAccountDir+serviceAccountTokenKey)
		}
		log.Debugf("Got secret %d bytes", len(b))
	}

	return c, nil
}

func (c *clusterClient) createRequest(uri string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest("GET", c.apiURL+uri, body)
	if err != nil {
		return nil, err
	}

	if c.tokenProvider != nil {
		token, ok := c.tokenProvider.GetSecret(serviceAccountDir + serviceAccountTokenKey)
		if !ok {
			return nil, fmt.Errorf("secret not found: %v", serviceAccountDir+serviceAccountTokenKey)
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
	}

	return req, nil
}

func (c *clusterClient) getJSON(uri string, a interface{}) error {
	log.SetLevel(log.DebugLevel)
	log.Debugf("making request to: %s", uri)

	req, err := c.createRequest(uri, nil)
	if err != nil {
		return err
	}

	rsp, err := c.httpClient.Do(req)
	if err != nil {
		log.Debugf("request to %s failed: %v", uri, err)
		return err
	}

	log.Debugf("request to %s succeeded", uri)
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusNotFound {
		return errResourceNotFound
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("request failed, status: %d, %s", rsp.StatusCode, rsp.Status)
		return fmt.Errorf("request failed, status: %d, %s", rsp.StatusCode, rsp.Status)
	}

	b := bytes.NewBuffer(nil)
	if _, err := io.Copy(b, rsp.Body); err != nil {
		log.Debugf("reading response body failed: %v", err)
		return err
	}
	buf := b.Bytes()

	err = json.Unmarshal(buf, a)
	if err != nil {
		log.Debugf("invalid response format: %v", err)
		return err
	}

	return err
}

func (c *clusterClient) loadFabricgateways() ([]*Fabric, error) {
	var fl FabricList
	err := c.getJSON(FabricGatewayURI, &fl)
	if err != nil {
		return nil, err
	}

	println("FabricList len(items):", len(fl.Items))

	fcs := make([]*Fabric, 0, len(fl.Items))
	for _, fg := range fl.Items {
		err := ValidateFabricResource(fg)
		if err != nil {
			log.Errorf("Failed to validate: %v", err)
		}
		fcs = append(fcs, fg)
	}

	return fcs, nil
}

func NewFabricDataClient(o Options) (*FabricDataClient, error) {
	quit := make(chan struct{})

	apiURL, err := buildAPIURL(o)
	if err != nil {
		return nil, err
	}

	clusterClient, err := newClusterClient(o, apiURL, quit)
	if err != nil {
		return nil, err
	}

	return &FabricDataClient{
		quit:          quit,
		ClusterClient: clusterClient,
	}, nil
}

func (fdc *FabricDataClient) Close() {
	close(fdc.quit)
}

func createRouteID(name, namespace, host, path, method string) string {
	namespace = nonWord.ReplaceAllString(namespace, "_")
	name = nonWord.ReplaceAllString(name, "_")
	host = nonWord.ReplaceAllString(host, "_")
	path = nonWord.ReplaceAllString(path, "_")
	method = nonWord.ReplaceAllString(method, "_")

	return fmt.Sprintf("fg_%s_%s_%s_%s_%s", namespace, name, host, path, method)
}

// getKubeSvc returns serviceName, portName, portNumber, if portName is emtpy,
// portNumber will have a non zero number.
func getKubeSvc(fabsvc *FabricService) (string, string, int) {
	var (
		portName   string
		portNumber int
		err        error
	)
	portNumber, err = strconv.Atoi(fabsvc.ServicePort)
	if err != nil {
		portName = fabsvc.ServicePort
	}

	return fabsvc.ServiceName, portName, portNumber
}

func convertOne(fg *Fabric) ([]*eskip.Route, error) {
	routes := make([]*eskip.Route, 0)

	for _, fabsvc := range fg.Spec.Service {
		host := fabsvc.Host
		svcName, svcPortName, svcPortNumber := getKubeSvc(fabsvc)
		log.Debugf("fabsvc host=%s svc=%s portName=%s, portNumber=%d", host, svcName, svcPortName, svcPortNumber)

		for _, p := range fg.Spec.Paths.Path {
			println("fg:", fg.Metadata.Namespace, fg.Metadata.Name, "with host", host, "with path:", p.Path, "methods:", len(p.Methods))
			for _, m := range p.Methods {
				// TODO(sszuecs): make sure we create the routes correctly, this is just a stub
				r := &eskip.Route{
					Id:     createRouteID(fg.Metadata.Namespace, fg.Metadata.Name, host, p.Path, m.Method),
					Path:   p.Path,
					Method: m.Method,
					Predicates: []*eskip.Predicate{
						{
							Name: predicates.HeaderName,
							Args: []interface{}{
								"X-Forwarded-Proto",
								"https",
							},
						},
						{
							Name: predicates.WeightName,
							Args: []interface{}{
								23, // TODO(sszuecs) needs checking
							},
						},
					},
				}
				routes = append(routes, r)
			}
		}
	}

	// TODO(sszuecs): make sure errors are reported
	// fmt.Errorf("failed to convert fabricgateway %s/%s: %v", fg.Metadata.Namespace, fg.Metadata.Name, err)
	return routes, nil
}

func (fdc *FabricDataClient) convert(fgs []*Fabric) ([]*eskip.Route, error) {
	routes := make([]*eskip.Route, 0, len(fgs))
	for _, fg := range fgs {
		r, err := convertOne(fg)
		if err != nil {
			log.Errorf("Ignore: %v", err)
			continue
		}

		routes = append(routes, r...)
	}
	return routes, nil
}

func (fdc *FabricDataClient) LoadAll() ([]*eskip.Route, error) {
	fgs, err := fdc.ClusterClient.loadFabricgateways()
	if err != nil {
		return nil, err
	}

	return fdc.convert(fgs)
}

func (fdc *FabricDataClient) LoadUpdate() ([]*eskip.Route, []string, error) {
	return nil, nil, nil
}
