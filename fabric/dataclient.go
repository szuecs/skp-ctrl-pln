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
	zv1 "github.com/szuecs/skp-ctrl-pln/fabric/stackset/v1"
	"github.com/zalando/skipper/dataclients/kubernetes/definitions"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/flowid"
	"github.com/zalando/skipper/loadbalancer"
	"github.com/zalando/skipper/predicates"
	"github.com/zalando/skipper/secrets"
	"k8s.io/apimachinery/pkg/util/intstr"
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

// TODO(sszuecs): these should be configurable by dataclient configuration
var (
	// filter args
	checkEmployeeFilterArgs          = []interface{}{"realm", "/employees"}
	checkServiceFilterArgs           = []interface{}{"realm", "/services"}
	checkEmployeeOrServiceFilterArgs = append(checkServiceFilterArgs, checkEmployeeFilterArgs...)
	checkCommonScopeFilterArgs       = []interface{}{"uid"}
	logCommonKeyFilterArgs           = []interface{}{"sub"}
	forwardTokenFilterArgs           = []interface{}{
		"X-TokenInfo-Forward",
		"uid",
		"scope",
		"realm",
	}
	forwardTokenEmployeeFilterArgs = []interface{}{
		"X-TokenInfo-Forward",
		"uid",
		"realm",
	}
	clusterClientRatelimitHeader = "Authorization"

	// predicate args
	uidKey                      = "https://identity.zalando.com/managed-id"
	checkUserRealmPredicateArgs = []interface{}{
		"https://identity.zalando.com/realm",
		"users",
	}
)

var (
	errResourceNotFound     = errors.New("resource not found")
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
}

type FabricDataClient struct {
	quit          chan struct{}
	ClusterClient *clusterClient
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
	defaultEndpoints := []string{
		"http://10.2.23.42:8080",
		"http://10.2.5.4:8080",
	}

	if strings.HasPrefix(namespace, "traffic-") {
		a := strings.Split(namespace, "-")
		if len(a) != 2 {
			return defaultEndpoints
		}
		w := a[1]
		n, err := strconv.Atoi(w)
		if err != nil {
			return defaultEndpoints
		}
		eps := make([]string, 0, n)
		for i := 0; i < n; i++ {
			eps = append(eps, fmt.Sprintf("http://10.2.100.1%d:8088", i))
		}
		return eps
	}
	return defaultEndpoints
}

// dummy
func getStacksetTrafficByName(namespace, name string) []*zv1.ActualTraffic {
	return []*zv1.ActualTraffic{
		{
			StackName:   "s1",
			ServiceName: "svc1",
			ServicePort: intstr.FromString("ingress"),
			Weight:      30,
		},
		{
			StackName:   "s2",
			ServiceName: "svc2",
			ServicePort: intstr.FromInt(8080),
			Weight:      30,
		},
		{
			StackName:   "s3",
			ServiceName: "svc3",
			ServicePort: intstr.FromInt(8081),
			Weight:      30,
		},
	}
}

// decideAllowedServices returns a definitive list of allowed services as a result of
// inspecting both global (default) and local (specified on path/method) allow list.
// Output should be interpreted as follows:
// - nil: all services are allowed
// - empty slice: no services are allowed
// - non-empty slice: a list of allowed services
func decideAllowedServices(globalAllowList []string, localAllowList *FabricAllowList) []string {
	if localAllowList != nil {
		if localAllowList.State == "disabled" {
			return nil
		} else {
			return localAllowList.UIDs
		}
	} else {
		return globalAllowList
	}
}

func allowedServicesToFilterArgs(allowedServices []string) []interface{} {
	var filterArgs []interface{}
	for _, svcName := range allowedServices {
		filterArgs = append(filterArgs, "sub", svcName)
	}

	return filterArgs
}

func applyCompression(r *eskip.Route, fc *FabricCompression) {
	if fc == nil {
		return
	}

	r.Filters = append(r.Filters, &eskip.Filter{
		Name: "compress",
		Args: []interface{}{
			fc.Factor,
			fc.Encoding,
		},
	})
}

func convertOne(fg *Fabric) ([]*eskip.Route, error) {
	routes := make([]*eskip.Route, 0)

	lbAlgorithm := loadbalancer.RoundRobin.String()
	if s, ok := fg.Metadata.Annotations[skipperLoadBalancerAnnotationKey]; ok {
		lbAlgorithm = s
	}

	// x-fabric-admins preparation
	var adminArgs []interface{}
	if admins := fg.Spec.Admins; len(admins) != 0 {
		adminArgs = make([]interface{}, 0, 2*len(admins))
		for _, s := range admins {
			adminArgs = append(adminArgs, uidKey, s)
		}
	}

	// x-fabric-cors-support preparation
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

	// x-external-service-provider
	if esp := fg.Spec.ExternalServiceProvider; esp != nil {
		// TODO(sszuecs) use clusterclient instead of this dummy to fetch online resources, but here we only care that we get something in case of x-external-service-provider is set
		trs := getStacksetTrafficByName(fg.Metadata.Namespace, fg.Metadata.Name)

		weightsMap, noopCount := calculateTraffic(trs)

		globalHostRouteDone := false
		for i, traffic := range trs {
			if traffic.Weight <= 0 {
				continue
			}

			var trafficParam float64
			if v, ok := weightsMap[traffic.ServiceName]; ok {
				trafficParam = v
			} else {
				continue
			}

			ridSuffix := ""
			if i >= 0 {
				ridSuffix = "_" + strconv.Itoa(i)
			}
			println("trafficParam:", trafficParam, "noopCount:", noopCount, "ridSuffix:", ridSuffix)

			// TODO(sszuecs): fix how to get endpoints
			endpoints := getEndpointsByService(fg.Metadata.Namespace, traffic.ServiceName, "tcp", &servicePort{
				Name: traffic.ServicePort.StrVal,
				Port: traffic.ServicePort.IntValue(),
			})
			// TODO(sszuecs): maybe check that endpoints are not 0, but what if all of them are 0. Maybe better to shortcute the routes with `status(502) -> <shunt>` in this case.

			for _, host := range esp.Hosts {
				log.Debugf("x-external-service-provider host=%s svc=%s portName=%s, portNumber=%d", host, traffic.ServiceName, traffic.ServicePort.StrVal, traffic.ServicePort.IntValue())

				routes = append(routes, createRoutes(fg, globalHostRouteDone, trafficParam, noopCount, ridSuffix, host, lbAlgorithm, endpoints, adminArgs, allowedOrigins)...)
			}
			globalHostRouteDone = true
			noopCount--
		}

	}

	// x-fabric-service
	for _, fabsvc := range fg.Spec.Service {
		host := fabsvc.Host

		// TODO(sszuecs): cleanup this hack and think about ingress v1, do we want to change svc def in Fabric?
		svcName, svcPortName, svcPortNumber := getKubeSvc(fabsvc)
		// TODO(sszuecs): fix how to get endpoints
		endpoints := getEndpointsByService(fg.Metadata.Namespace, svcName, "tcp", &servicePort{
			Name: svcPortName,
			Port: svcPortNumber,
		})
		log.Debugf("fabsvc host=%s svc=%s portName=%s, portNumber=%d", host, svcName, svcPortName, svcPortNumber)

		routes = append(routes, createRoutes(fg, false, -1, -1, "", host, lbAlgorithm, endpoints, adminArgs, allowedOrigins)...)

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

// calculateTraffic returns parameters that can be feed into Traffic()
// predicates and the max count of True() predicates to be used and to
// be decreased by the user of this function.
func calculateTraffic(trs []*zv1.ActualTraffic) (map[string]float64, int) {
	trafficMap := make(map[string]float64)
	noopCount := 0
	var weightsSum float64
	for _, traffic := range trs {
		if traffic.Weight <= 0 {
			continue
		}
		trafficMap[traffic.ServiceName] = traffic.Weight
		weightsSum += traffic.Weight
		noopCount += 1
	}
	noopCount -= 2 // 1 route has no Traffic(), 1 route has only Traffic(), and rest needs True()s
	if noopCount < 0 {
		noopCount = 0
	}

	keys := make([]string, 0, len(trafficMap))
	for k := range trafficMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// used to pass to createRoutes() as the arg in Traffic(arg).
	restIterations := len(trafficMap) - 1
	weightsMap := make(map[string]float64)
	for _, k := range keys {
		if restIterations == 0 {
			weightsMap[k] = float64(-1) // last has no Traffic() or we loose traffic
			break
		}
		v := trafficMap[k]
		weightsMap[k] = v / weightsSum
		weightsSum -= v
		restIterations -= 1
	}

	return weightsMap, noopCount
}

func createRoutes(fg *Fabric, hostGlobalRouteDone bool, trafficParam float64, noopCount int, ridSuffix, host, lbAlgorithm string, endpoints []string, adminArgs, allowedOrigins []interface{}) []*eskip.Route {
	routes := make([]*eskip.Route, 0)

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

	if !hostGlobalRouteDone {
		// 404 route per host
		r404 := create404Route(create404RouteID(fg, host), host, defaultScopePrivileges)
		routes = append(routes, r404)

		// reject plain http per host with 400, but not for internal routes
		if !strings.HasSuffix(host, ".cluster.local") {
			reject400 := createRejectRoute(createRejectRouteID(fg, host), host, defaultScopePrivileges)
			routes = append(routes, reject400)
		}
	}

	for _, fp := range fg.Spec.Paths.Path {
		methods := make([]string, 0, len(fp.Methods))
		for _, m := range fp.Methods {
			methods = append(methods, m.Method)

			// AllowList per method and global default
			//     example: oauthTokeninfoAllScope("uid", "foo.write")
			var privs []interface{}
			privs = append(privs, defaultScopePrivileges...)
			for _, priv := range m.Privileges {
				privs = append(privs, priv)
			}

			allowedServices := decideAllowedServices(fg.Spec.AllowList, m.AllowList)
			if len(allowedServices) > 0 || allowedServices == nil {
				r := createServiceRoute(m, eskipBackend, allowedOrigins, allowedServicesToFilterArgs(allowedServices), privs, fg.Metadata.Name, fg.Metadata.Namespace, host, fp.Path, ridSuffix)
				applyPath(r, fp)
				applyCompression(r, fg.Spec.Compression)
				applyStaticResponse(r, m.Response)
				applyTraffic(r, trafficParam)
				applyNoops(r, noopCount)
				routes = append(routes, r)

				// ratelimit overrrides require separated routes with predicates.JWTPayloadAllKVName
				if m.Ratelimit != nil && len(m.Ratelimit.Target) > 0 {
					routes = append(routes, createRatelimitRoutes(r, m, fg.Metadata.Name, fp.Path)...)
				}
			}

			// routes to support x-fabric-employee-access
			if m.EmployeeAccess != nil {
				usersAllowed := make([]interface{}, 0, 2*len(m.EmployeeAccess.UserList))
				sort.Strings(m.EmployeeAccess.UserList)
				for _, u := range m.EmployeeAccess.UserList {
					usersAllowed = append(usersAllowed, uidKey, u)
				}
				rea := createEmployeeAccessRoute(m, eskipBackend, allowedOrigins, usersAllowed, m.EmployeeAccess.Type, fg.Metadata.Name, fg.Metadata.Namespace, host, fp.Path, ridSuffix)
				applyPath(rea, fp)
				applyCompression(rea, fg.Spec.Compression)
				applyStaticResponse(rea, m.Response)
				applyTraffic(rea, trafficParam)
				applyNoops(rea, noopCount)
				routes = append(routes, rea)
			}

			// routes to support x-fabric-admins
			if len(adminArgs) != 0 {
				// TODO(sszuecs): currently fabric would also do applyStaticResponse in case we have it for the route, let's discuss if it makes sense. https://github.com/zalando-incubator/fabric-gateway/pull/64 says it does make sense, because admins want to try that the static response is in place.
				ra := createAdminRoute(eskipBackend, createAdminRouteID(fg, host, fp.Path)+ridSuffix, host, fp.Path, m.Method, adminArgs, allowedOrigins)
				applyPath(ra, fp)
				applyCompression(ra, fg.Spec.Compression)
				applyStaticResponse(ra, m.Response)
				applyTraffic(ra, trafficParam)
				applyNoops(ra, noopCount)
				routes = append(routes, ra)
			}

		}

		if !hostGlobalRouteDone && fg.Spec.Cors != nil && len(allowedOrigins) > 0 {
			rID := createCorsRouteID(fg, host, fp.Path)
			corsMethods := strings.ToUpper(strings.Join(methods, ", "))
			if !strings.Contains(corsMethods, "OPTIONS") {
				corsMethods = corsMethods + ", OPTIONS"
			}
			corsAllowedHeaders := strings.Join(fg.Spec.Cors.AllowedHeaders, ", ")
			cr := createCorsRoute(rID, host, fp.Path, corsMethods, corsAllowedHeaders, methods, allowedOrigins)
			applyPath(cr, fp)
			applyTraffic(cr, trafficParam)
			applyNoops(cr, noopCount)
			routes = append(routes, cr)
		}
	}
	return routes
}

func create404Route(rid, host string, privs []interface{}) *eskip.Route {
	return &eskip.Route{
		Id: rid,
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.PathSubtreeName,
				Args: []interface{}{
					"/",
				},
			}, {
				Name: predicates.HostAnyName,
				Args: []interface{}{
					host,
					host + ":80",
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

func createRejectRoute(rid, host string, privs []interface{}) *eskip.Route {
	return &eskip.Route{
		Id: rid,
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.PathSubtreeName,
				Args: []interface{}{
					"/",
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

func createEmployeeAccessRoute(m *FabricMethod, eskipBackend *eskipBackend, allowedOrigins, userList []interface{}, accessType, name, namespace, host, path, ridSuffix string) *eskip.Route {
	r := &eskip.Route{
		Id:     createRouteID("fg_eaccess", name, namespace, host, path, m.Method) + ridSuffix,
		Method: strings.ToUpper(m.Method),
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.WeightName,
				Args: []interface{}{
					4, // TODO(sszuecs) needs checking
				},
			},
		},
		Filters: []*eskip.Filter{
			{
				// oauthTokeninfoAnyKV(realm", "/employees")
				Name: filters.OAuthTokeninfoAnyKVName,
				Args: checkEmployeeFilterArgs,
			},
			{
				// oauthTokeninfoAllScope("uid")
				Name: filters.OAuthTokeninfoAllScopeName,
				Args: checkCommonScopeFilterArgs,
			},
			{
				// unverifiedAuditLog("sub")
				Name: filters.UnverifiedAuditLogName,
				Args: logCommonKeyFilterArgs,
			},
		},
		BackendType: eskipBackend.Type,
		Backend:     eskipBackend.backend,
		LBAlgorithm: eskipBackend.lbAlgorithm,
		LBEndpoints: eskipBackend.lbEndpoints,
	}

	// add optional ratelimit only default ratelimit
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
				// clusterClientRatelimit("foo_.._users", 30, "1m", "Authorization")
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
					clusterClientRatelimitHeader,
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
				// forwardToken("X-TokenInfo-Forward", "uid", "realm")
				Name: filters.ForwardTokenName,
				Args: forwardTokenEmployeeFilterArgs,
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

	applyCommonPredicates(r, host)

	// x-fabric-employee-access specifics
	switch accessType {
	case "allow_all":
		// allow all
		r.Predicates = append(r.Predicates, &eskip.Predicate{
			Name: predicates.JWTPayloadAllKVName,
			Args: checkUserRealmPredicateArgs,
		})
	case "allow_list":
		r.Predicates = append(r.Predicates, &eskip.Predicate{
			Name: predicates.JWTPayloadAnyKVName,
			Args: userList,
		})
	case "deny_all":
		r.Predicates = append(r.Predicates, &eskip.Predicate{
			Name: predicates.JWTPayloadAllKVName,
			Args: checkUserRealmPredicateArgs,
		})
		// no need to process filters, reset filters and set backend to shunt
		r.Filters = []*eskip.Filter{
			{
				Name: filters.StatusName,
				Args: []interface{}{403}, // TODO(sszuecs): status similar to fg-controller?
			},
			{
				// TODO(sszuecs): what would the current FG-controller do to return a response message?
				Name: filters.InlineContentName,
				Args: []interface{}{
					`{"title":"Gateway Rejected","status":403,"detail":"deny all employees"}`,
				},
			},
		}
		r.BackendType = eskip.ShuntBackend
		r.Backend = ""
		r.LBAlgorithm = ""
		r.LBEndpoints = nil
	}

	return r
}

func applyStaticResponse(r *eskip.Route, static *FabricResponse) {
	if static != nil {
		r.BackendType = eskip.ShuntBackend
		r.Backend = ""
		r.LBAlgorithm = ""
		r.LBEndpoints = nil

		headers := make([]interface{}, 0, 2*len(static.Headers))
		for _, k := range getSortedKeysStr(static.Headers) {
			headers = append(headers, k)
			headers = append(headers, static.Headers[k])
		}

		r.Filters = append(r.Filters,
			// -> setResponseHeader("Content-Type", "application/problem+json")
			&eskip.Filter{
				Name: filters.SetResponseHeaderName,
				Args: headers,
			},
			// -> status(501)
			&eskip.Filter{
				Name: filters.StatusName,
				Args: []interface{}{static.StatusCode},
			},
			// -> inlineContent("{\"title\": \"Issues Updates Not Yet Supported\", \"status\": 501}")
			&eskip.Filter{
				Name: filters.InlineContentName,
				Args: []interface{}{
					static.Body,
				},
			},
		)
	}
}

func applyNoops(r *eskip.Route, noopCount int) {
	if noopCount < 1 {
		return
	}
	for i := 0; i < noopCount; i++ {
		r.Predicates = append(r.Predicates, &eskip.Predicate{
			Name: predicates.TrueName,
		})
	}
}

func applyTraffic(r *eskip.Route, trafficParam float64) {
	if trafficParam < 0 || trafficParam > 1 {
		return
	}
	r.Predicates = append(r.Predicates, &eskip.Predicate{
		Name: predicates.TrafficName,
		Args: []interface{}{
			trafficParam,
		},
	})
}

func applyCommonPredicates(r *eskip.Route, host string) {
	if !strings.HasSuffix(host, ".cluster.local") {
		r.Predicates = append(
			[]*eskip.Predicate{
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
			}, r.Predicates...)
	} else {
		r.Predicates = append(
			[]*eskip.Predicate{
				{
					Name: predicates.HostAnyName,
					Args: []interface{}{
						host,
						host + ":80",
					},
				},
			}, r.Predicates...)
	}
}

func createServiceRoute(m *FabricMethod, eskipBackend *eskipBackend, allowedOrigins, allowedServices, privs []interface{}, name, namespace, host, path, ridSuffix string) *eskip.Route {
	r := &eskip.Route{
		Id:     createRouteID("fg", name, namespace, host, path, m.Method) + ridSuffix,
		Method: strings.ToUpper(m.Method),
		Predicates: []*eskip.Predicate{
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
				Args: checkEmployeeOrServiceFilterArgs,
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
			Args: logCommonKeyFilterArgs,
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
					clusterClientRatelimitHeader,
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
				Args: forwardTokenFilterArgs,
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

	applyCommonPredicates(r, host)

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
				Args: append(logCommonKeyFilterArgs, rTarget.UID),
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

func createAdminRoute(eskipBackend *eskipBackend, routeID, host, path, method string, adminsArgs, allowedOrigins []interface{}) *eskip.Route {
	rr := &eskip.Route{
		Id:          routeID + "_" + strings.ToLower(method),
		BackendType: eskipBackend.Type,
		Backend:     eskipBackend.backend, // in case we have only 1 endpoint we fallback to network backend
		LBAlgorithm: eskipBackend.lbAlgorithm,
		LBEndpoints: eskipBackend.lbEndpoints,
		Method:      strings.ToUpper(method),
		Predicates: []*eskip.Predicate{
			{
				Name: predicates.WeightName,
				Args: []interface{}{5},
			},
			{
				Name: predicates.JWTPayloadAllKVName,
				Args: checkUserRealmPredicateArgs,
			},
			{
				Name: predicates.JWTPayloadAnyKVName,
				Args: adminsArgs,
			},
		},
		Filters: []*eskip.Filter{
			{
				// TODO(sszuecs): drop service realm for employees
				// oauthTokeninfoAnyKV("realm", "/services", "realm", "/employees")
				Name: filters.OAuthTokeninfoAnyKVName,
				Args: checkEmployeeOrServiceFilterArgs,
			}, {
				// enableAccessLog(2, 4, 5)
				Name: filters.EnableAccessLogName,
				Args: []interface{}{2, 4, 5},
			}, {
				// oauthTokeninfoAllScope("uid")
				Name: filters.OAuthTokeninfoAllScopeName,
				Args: checkCommonScopeFilterArgs,
			}, {
				// unverifiedAuditLog(uidKey)
				Name: filters.UnverifiedAuditLogName,
				Args: []interface{}{
					uidKey,
				},
			}, {
				// flowId("reuse")
				Name: filters.FlowIdName,
				Args: []interface{}{flowid.ReuseParameterValue},
			}, {
				// forwardToken("X-TokenInfo-Forward", "uid", "scope", "realm")
				Name: filters.ForwardTokenName,
				Args: forwardTokenFilterArgs,
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

	applyCommonPredicates(rr, host)

	return rr
}

func createCorsRoute(routeID, host, path, corsMethods, corsAllowedHeaders string, methods []string, allowedOrigins []interface{}) *eskip.Route {
	r := &eskip.Route{
		Id:          routeID,
		BackendType: eskip.ShuntBackend,
		Method:      "OPTIONS",
		Predicates: []*eskip.Predicate{
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

	applyCommonPredicates(r, host)
	return r
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
