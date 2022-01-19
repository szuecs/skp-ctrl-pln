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
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/dataclients/kubernetes/definitions"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/flowid"
	"github.com/zalando/skipper/loadbalancer"
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

	skipperLoadBalancerAnnotationKey = "zalando.org/skipper-loadbalancer"
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

type eskipBackend struct {
	Type        eskip.BackendType
	backend     string
	lbAlgorithm string
	lbEndpoints []string
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

func createRejectRouteID(fg *Fabric, host string) string {
	return createRouteID("fg_reject", fg.Metadata.Name, fg.Metadata.Namespace, host, "", "")
}

func create404RouteID(fg *Fabric, host string) string {
	return createRouteID("fg_404", fg.Metadata.Name, fg.Metadata.Namespace, host, "", "")
}

func createCorsRouteID(fg *Fabric, host, path string) string {
	return createRouteID("fg_cors", fg.Metadata.Name, fg.Metadata.Namespace, host, path, "")
}

func createAdminRouteID(fg *Fabric, host, path string) string {
	return createRouteID("fg_admin", fg.Metadata.Name, fg.Metadata.Namespace, host, path, "")
}

func createRouteID(prefix, name, namespace, host, path, method string) string {
	namespace = nonWord.ReplaceAllString(namespace, "_")
	name = nonWord.ReplaceAllString(name, "_")
	host = nonWord.ReplaceAllString(host, "_")
	path = nonWord.ReplaceAllString(path, "_")
	method = nonWord.ReplaceAllString(method, "_")

	return fmt.Sprintf("%s_%s_%s_%s_%s_%s", prefix, namespace, name, host, path, method)
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

// copied definition github.com/zalando/skipper/dataclients/kubernetes/ingressdefinitions.go
type servicePort struct {
	Name       string                   `json:"name"`
	Port       int                      `json:"port"`
	TargetPort *definitions.BackendPort `json:"targetPort"` // string or int
}

// signature copied from github.com/zalando/skipper/dataclients/kubernetes/clusterstate.go
// dummy
func getEndpointsByService(namespace, name, protocol string, servicePort *servicePort) []string {
	return []string{
		"http://10.2.23.42:8080",
		"http://10.2.5.4:8080",
	}
}

func convertOne(fg *Fabric) ([]*eskip.Route, error) {
	routes := make([]*eskip.Route, 0)

	lbAlgorithm := loadbalancer.RoundRobin.String()
	if s, ok := fg.Metadata.Annotations[skipperLoadBalancerAnnotationKey]; ok {
		lbAlgorithm = s
	}

	var allowedOrigins []interface{}
	if fg.Spec.Cors != nil {
		cors := fg.Spec.Cors
		allowedOrigins = make([]interface{}, 0, len(cors.AllowedOrigins))
		sort.Strings(cors.AllowedOrigins)
		for _, w := range cors.AllowedOrigins {
			// explicitly disallow * by design
			if w != "*" {
				allowedOrigins = append(allowedOrigins, "https://"+w)
			}
		}
	}

	for _, fabsvc := range fg.Spec.Service {
		host := fabsvc.Host

		// TODO(sszuecs): cleanup this hack and think about ingress v1, do we want to change svc def in Fabric?
		svcName, svcPortName, svcPortNumber := getKubeSvc(fabsvc)
		// TODO(sszuecs): fix how to get endpoints
		endpoints := getEndpointsByService(fg.Metadata.Namespace, fg.Metadata.Name, "tcp", &servicePort{
			Name: svcPortName,
			Port: svcPortNumber,
		})
		log.Debugf("fabsvc host=%s svc=%s portName=%s, portNumber=%d", host, svcName, svcPortName, svcPortNumber)

		be := ""
		var bt eskip.BackendType = eskip.LBBackend
		if len(endpoints) == 1 {
			be = endpoints[0]
			bt = eskip.NetworkBackend
			endpoints = nil
		}
		eskipBackend := &eskipBackend{
			Type:        bt,
			backend:     be,
			lbAlgorithm: lbAlgorithm,
			lbEndpoints: endpoints,
		}

		defaultScopePrivileges := []interface{}{
			"uid",
		}
		var defaultAllowList []interface{}
		for _, app := range fg.Spec.AllowList {
			defaultAllowList = append(defaultAllowList, "sub", app)
		}

		// 404 route per host
		r404 := create404Route(create404RouteID(fg, host), "/", host, defaultScopePrivileges)
		routes = append(routes, r404)

		// reject plain http per host with 400, but not for internal routes
		if !strings.HasSuffix(host, ".cluster.local") {
			reject400 := createRejectRoute(createRejectRouteID(fg, host), "/", host, defaultScopePrivileges)
			routes = append(routes, reject400)
		}

		for _, p := range fg.Spec.Paths.Path {
			// TODO(sszuecs): cleanup
			println("fg:", fg.Metadata.Namespace, fg.Metadata.Name, "with host", host, "with path:", p.Path, "methods:", len(p.Methods))
			methods := make([]string, 0, len(p.Methods))
			for _, m := range p.Methods {
				methods = append(methods, m.Method)

				// AllowList per method and global default
				//     example: oauthTokeninfoAllScope("uid", "foo.write")
				var privs []interface{}
				privs = append(privs, defaultScopePrivileges...)
				for _, priv := range m.Privileges {
					privs = append(privs, priv)
				}

				// local allowlist overrides default. In case allow list is disabled only use scopes.
				//     example: oauthTokeninfoAnyKV("sub", "app1", "sub", "app2", ..)
				var allowedServices []interface{}
				disableAllowList := false
				if m.AllowList != nil {
					switch m.AllowList.State {
					case "disabled":
						disableAllowList = true
					default:
						for _, svcName := range m.AllowList.UIDs {
							// TODO(sszuecs): in the future "sub" should be configurable
							allowedServices = append(allowedServices, "sub", svcName)
						}
					}
				} else {
					allowedServices = append(allowedServices, defaultAllowList...)
				}

				if disableAllowList || len(allowedServices) > 0 || m.AllowList == nil {
					// normal host+path+method service route
					r := createServiceRoute(m, eskipBackend, allowedOrigins, allowedServices, privs, fg.Metadata.Name, fg.Metadata.Namespace, host, p.Path)
					routes = append(routes, r)

					// ratelimit overrrides require separated routes with predicates.JWTPayloadAllKVName
					if m.Ratelimit != nil && len(m.Ratelimit.Target) > 0 {
						routes = append(routes, createRatelimitRoutes(r, m, fg.Metadata.Name, p.Path)...)
					}
				}
			}

			if fg.Spec.Cors != nil && len(allowedOrigins) > 0 {
				rID := createCorsRouteID(fg, host, p.Path)
				corsMethods := strings.ToUpper(strings.Join(methods, ", "))
				if !strings.Contains(corsMethods, "OPTIONS") {
					corsMethods = corsMethods + ", OPTIONS"
				}
				corsAllowedHeaders := strings.Join(fg.Spec.Cors.AllowedHeaders, ", ")
				routes = append(routes, createCorsRoute(rID, host, p.Path, corsMethods, corsAllowedHeaders, methods, allowedOrigins))
			}
			if len(fg.Spec.Admins) != 0 {
				rID := createAdminRouteID(fg, host, p.Path)
				adminRoutes := createAdminRoutes(eskipBackend, rID, host, p.Path, methods, fg.Spec.Admins, allowedOrigins)
				routes = append(routes, adminRoutes...)

			}
		}
	}

	// TODO(sszuecs): make sure errors are reported
	// fmt.Errorf("failed to convert fabricgateway %s/%s: %v", fg.Metadata.Namespace, fg.Metadata.Name, err)

	fd, err := os.Create("/tmp/foo.eskip")
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	eskip.Fprint(fd, eskip.PrettyPrintInfo{Pretty: true, IndentStr: "\t"}, routes...)

	return routes, nil
}

func stringToEmptyInterface(a []string) []interface{} {
	res := make([]interface{}, len(a))
	for i := range a {
		res[i] = a[i]
	}
	return res
}

func create404Route(rid, path, host string, privs []interface{}) *eskip.Route {
	return &eskip.Route{
		Id: rid,
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.PathSubtreeName,
				Args: []interface{}{
					path,
				},
			}, {
				Name: predicates.HostAnyName,
				Args: []interface{}{
					host,
					host + ":443",
				},
			},
		},
		Filters: []*eskip.Filter{
			{
				Name: filters.OAuthTokeninfoAllScopeName,
				Args: privs,
			}, {
				Name: filters.UnverifiedAuditLogName,
				Args: []interface{}{
					"sub",
				},
			}, {
				Name: filters.StatusName,
				Args: []interface{}{
					404,
				},
			}, {
				Name: filters.InlineContentName,
				Args: []interface{}{
					`{"title":"Gateway Rejected","status":404,"detail":"Gateway Route Not Matched"}`,
				},
			},
		},
		BackendType: eskip.ShuntBackend,
	}
}

func createRejectRoute(rid, path, host string, privs []interface{}) *eskip.Route {
	return &eskip.Route{
		Id: rid,
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.PathSubtreeName,
				Args: []interface{}{
					path,
				},
			}, {
				Name: predicates.HostAnyName,
				Args: []interface{}{
					host,
					host + ":443",
				},
			}, {
				Name: predicates.HeaderName,
				Args: []interface{}{
					"X-Forwarded-Proto",
					"http",
				},
			},
		},
		Filters: []*eskip.Filter{
			{
				Name: filters.OAuthTokeninfoAllScopeName,
				Args: privs,
			}, {
				Name: filters.UnverifiedAuditLogName,
				Args: []interface{}{
					"sub",
				},
			}, {
				Name: filters.StatusName,
				Args: []interface{}{
					400,
				},
			}, {
				Name: filters.InlineContentName,
				Args: []interface{}{
					`{"title":"Gateway Rejected","status":400,"detail":"TLS is required","type":"https://cloud.docs.zalando.net/howtos/ingress/#redirect-http-to-https"}`,
				},
			},
		},
		BackendType: eskip.ShuntBackend,
	}
}

func createServiceRoute(m *FabricMethod, eskipBackend *eskipBackend, allowedOrigins, allowedServices, privs []interface{}, name, namespace, host, path string) *eskip.Route {
	r := &eskip.Route{
		Id:     createRouteID("fg", name, namespace, host, path, m.Method),
		Path:   path,
		Method: strings.ToUpper(m.Method),
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.HostAnyName,
				Args: []interface{}{
					host,
					host + ":443",
				},
			},
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
		Filters: []*eskip.Filter{
			{
				// oauthTokeninfoAnyKV("realm", "/services", "realm", "/employees")
				Name: filters.OAuthTokeninfoAnyKVName,
				Args: []interface{}{
					// TODO(sszuecs): should be configurable
					"realm",
					"/services",
					"realm",
					"/employees",
				},
			},
			{
				// oauthTokeninfoAllScope("uid", "foo.write")
				Name: filters.OAuthTokeninfoAllScopeName,
				Args: privs,
			},
		},
		BackendType: eskipBackend.Type,
		Backend:     eskipBackend.backend,
		LBAlgorithm: eskipBackend.lbAlgorithm,
		LBEndpoints: eskipBackend.lbEndpoints,
	}

	// allow list via x-fabric-whitelist configuration
	if len(allowedServices) > 0 {
		// oauthTokeninfoAnyKV("sub", "my-app1", "sub", "my-app2")
		r.Filters = append(r.Filters,
			&eskip.Filter{
				Name: filters.OAuthTokeninfoAnyKVName,
				Args: allowedServices,
			},
		)
	}

	r.Filters = append(r.Filters,
		&eskip.Filter{
			// unverifiedAuditLog("sub")
			Name: filters.UnverifiedAuditLogName,
			Args: []interface{}{
				// TODO(sszuecs): in the future should be configurable
				"sub",
			},
		},
	)

	// add optional ratelimit (default ratelimit here, overrides later below adding new routes)
	if m.Ratelimit != nil {
		r.Filters = append(r.Filters,
			&eskip.Filter{
				//inlineContentIfStatus(429, "{\"title\": \"Rate limit exceeded\", \"detail\": \"See the retry-after header for how many seconds to wait before retrying.\", \"status\": 429}", "application/problem+json")
				Name: filters.InlineContentIfStatusName,
				Args: []interface{}{
					429,
					"{\"title\":\"Rate limit exceeded\",\"detail\":\"See the retry-after header for how many seconds to wait before retrying.\",\"status\":429}",
					"application/problem+json",
				},
			},
			&eskip.Filter{
				// clusterClientRatelimit("spp-brand-service_api-brand-assignments-id_DELETE", 30, "1m", "Authorization")
				Name: filters.ClusterClientRatelimitName,
				Args: []interface{}{
					// TODO(sszuecs): maybe we want to add namespace here, too (assume people could use namespaces to separate prod/staging, this would otherwise count both)
					fmt.Sprintf("%s_%s_%s",
						name,
						strings.Trim(nonWord.ReplaceAllString(path, "-"), "-"),
						m.Method,
					),
					m.Ratelimit.DefaultRate,
					m.Ratelimit.Period,
					// optional header, TODO(sszuecs): maybe configurable in the future
					"Authorization",
				},
			},
		)
	}

	// add rest filters
	r.Filters = append(r.Filters,
		[]*eskip.Filter{
			{
				// flowId("reuse")
				Name: filters.FlowIdName,
				Args: []interface{}{
					flowid.ReuseParameterValue,
				},
			},
			{
				// forwardToken("X-TokenInfo-Forward", "uid", "scope", "realm")
				Name: filters.ForwardTokenName,
				Args: []interface{}{
					// TODO(sszuecs): in the future should be configurable
					"X-TokenInfo-Forward",
					"uid",
					"scope",
					"realm",
				},
			},
		}...)

	// optional cors
	if len(allowedOrigins) > 0 {
		r.Filters = append(r.Filters,
			&eskip.Filter{
				// corsOrigin("https://foo.example.org", "https://bar.example.com")
				Name: filters.CorsOriginName,
				Args: allowedOrigins,
			},
		)
	}

	return r
}

func createRatelimitRoutes(r *eskip.Route, m *FabricMethod, name, path string) []*eskip.Route {
	routes := make([]*eskip.Route, 0, len(m.Ratelimit.Target))

	for i, rTarget := range m.Ratelimit.Target {
		rr := eskip.Copy(r)
		rr.Id = fmt.Sprintf("%s%d", rr.Id, i)

		// add predicate to match client application
		rr.Predicates = append(rr.Predicates,
			&eskip.Predicate{
				Name: predicates.JWTPayloadAllKVName,
				Args: []interface{}{
					"sub", // TODO(sszuecs) maybe configurable in the future
					rTarget.UID,
				},
			},
		)

		// find and replace ratelimit: type, group, rate. period stays the same
		for j := range rr.Filters {
			if rr.Filters[j].Name == filters.ClusterClientRatelimitName {
				// replace clusterClientRatelimit with clusterRatelimit,
				// because we have separate routes per UID and we can scale
				// shards with clusterRatelimit
				rr.Filters[j].Name = filters.ClusterRatelimitName
				rr.Filters[j].Args = []interface{}{
					fmt.Sprintf("%s_%s_%s_%s",
						name,
						strings.Trim(nonWord.ReplaceAllString(path, "-"), "-"),
						m.Method,
						rTarget.UID,
					),
					rTarget.Rate,
					m.Ratelimit.Period,
				}
			}
		}
		routes = append(routes, rr)
	}
	return routes

}

func createAdminRoutes(eskipBackend *eskipBackend, routeID, host, path string, methods, admins []string, allowedOrigins []interface{}) []*eskip.Route {
	adminsArgs := make([]interface{}, 0, 2*len(admins))
	for _, s := range admins {
		// TODO(sszuecs): this should be configurable
		adminsArgs = append(adminsArgs, "https://identity.zalando.com/managed-id", s)
	}

	r := make([]*eskip.Route, 0, len(methods))
	for _, m := range methods {
		rr := &eskip.Route{
			Id:          routeID + "_" + strings.ToLower(m),
			BackendType: eskipBackend.Type,
			Backend:     eskipBackend.backend, // in case we have only 1 endpoint we fallback to network backend
			LBAlgorithm: eskipBackend.lbAlgorithm,
			LBEndpoints: eskipBackend.lbEndpoints,
			Path:        path,
			Method:      strings.ToUpper(m),
			Predicates: []*eskip.Predicate{
				{
					Name: predicates.HostAnyName,
					Args: []interface{}{
						host,
						host + ":443",
					},
				},
				{
					Name: predicates.HeaderName,
					Args: []interface{}{
						"X-Forwarded-Proto",
						"https",
					},
				},
				{
					Name: predicates.WeightName,
					Args: []interface{}{5},
				},
				{
					Name: predicates.JWTPayloadAllKVName,
					Args: []interface{}{
						// TODO(sszuecs): this should be configurable
						"https://identity.zalando.com/realm",
						"users",
					},
				},
				{
					Name: predicates.JWTPayloadAnyKVName,
					Args: adminsArgs,
				},
			},
			Filters: []*eskip.Filter{
				{
					// oauthTokeninfoAnyKV("realm", "/services", "realm", "/employees")
					Name: filters.OAuthTokeninfoAnyKVName,
					Args: []interface{}{
						// TODO(sszuecs): should be configurable
						"realm",
						"/services", // TODO(sszuecs): seems not to be required for admin routes
						"realm",
						"/employees",
					},
				}, {
					// enableAccessLog(2, 4, 5)
					Name: filters.EnableAccessLogName,
					Args: []interface{}{2, 4, 5},
				}, {
					// oauthTokeninfoAllScope("uid")
					Name: filters.OAuthTokeninfoAllScopeName,
					// TODO(sszuecs): in the future should be configurable, maybe defaultprivileges
					Args: []interface{}{"uid"},
				}, {
					// unverifiedAuditLog("https://identity.zalando.com/managed-id")
					Name: filters.UnverifiedAuditLogName,
					Args: []interface{}{
						// TODO(sszuecs): in the future should be configurable
						"https://identity.zalando.com/managed-id",
					},
				}, {
					// flowId("reuse")
					Name: filters.FlowIdName,
					Args: []interface{}{flowid.ReuseParameterValue},
				}, {
					// forwardToken("X-TokenInfo-Forward", "uid", "scope", "realm")
					Name: filters.ForwardTokenName,
					Args: []interface{}{
						// TODO(sszuecs): in the future should be configurable
						"X-TokenInfo-Forward",
						"uid",
						"scope",
						"realm",
					},
				},
			},
		}
		if len(allowedOrigins) > 0 {
			rr.Filters = append(rr.Filters, &eskip.Filter{
				// corsOrigin("https://example.org", "https://example.com")
				Name: filters.CorsOriginName,
				Args: allowedOrigins,
			})
		}
		r = append(r, rr)
	}
	return r
}

func createCorsRoute(routeID, host, path, corsMethods, corsAllowedHeaders string, methods []string, allowedOrigins []interface{}) *eskip.Route {
	return &eskip.Route{
		Id:          routeID,
		BackendType: eskip.ShuntBackend,
		Method:      "OPTIONS",
		Path:        path,
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.HostAnyName,
				Args: []interface{}{
					host,
					host + ":443",
				},
			},
			{
				Name: predicates.HeaderName,
				Args: []interface{}{
					"X-Forwarded-Proto",
					"https",
				},
			},
			{
				Name: predicates.WeightName,
				Args: []interface{}{3},
			},
		},
		Filters: []*eskip.Filter{
			{
				//status(204)
				Name: filters.StatusName,
				Args: []interface{}{204},
			}, {
				// flowId("reuse")
				Name: filters.FlowIdName,
				Args: []interface{}{flowid.ReuseParameterValue},
			}, {
				// corsOrigin("https://example.org", "https://example.com")
				Name: filters.CorsOriginName,
				Args: allowedOrigins,
			}, {
				// appendResponseHeader("Access-Control-Allow-Methods", "DELETE, GET, OPTIONS")
				Name: filters.AppendResponseHeaderName,
				Args: stringToEmptyInterface([]string{"Access-Control-Allow-Methods", corsMethods}),
			}, {
				// appendResponseHeader("Access-Control-Allow-Headers", "authorization, ot-tracer-sampled, ot-tracer-spanid, ot-tracer-traceid")
				Name: filters.AppendResponseHeaderName,
				Args: stringToEmptyInterface([]string{"Access-Control-Allow-Headers", corsAllowedHeaders}),
			},
		},
	}
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
