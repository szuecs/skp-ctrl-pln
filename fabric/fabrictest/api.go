package fabrictest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/davecgh/go-spew/spew"
	yaml2 "github.com/ghodss/yaml"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/szuecs/skp-ctrl-pln/fabric"
	"github.com/zalando/skipper/dataclients/kubernetes"
)

var errInvalidFixture = errors.New("invalid fixture")

type TestAPIOptions struct {
	FailOn             []string `yaml:"failOn"`
	FindNot            []string `yaml:"findNot"`
	DisableRouteGroups bool     `yaml:"disableRouteGroups"`
}

type namespace struct {
	services       []byte
	ingresses      []byte
	fabricgateways []byte
	routeGroups    []byte
	endpoints      []byte
}

type api struct {
	failOn       map[string]bool
	findNot      map[string]bool
	namespaces   map[string]namespace
	all          namespace
	pathRx       *regexp.Regexp
	resourceList []byte
}

func NewAPI(o TestAPIOptions, specs ...io.Reader) (*api, error) {
	a := &api{
		namespaces: make(map[string]namespace),
		pathRx: regexp.MustCompile(
			"(/namespaces/([^/]+))?/(services|ingresses|routegroups|endpoints|fabricgateways)",
		),
	}

	var clr kubernetes.ClusterResourceList
	clr.Items = append(clr.Items, &kubernetes.ClusterResource{Name: fabric.FabricGatewayName})

	a.failOn = mapStrings(o.FailOn)
	a.findNot = mapStrings(o.FindNot)

	clrb, err := json.Marshal(clr)
	if err != nil {
		return nil, err
	}

	a.resourceList = clrb

	namespaces := make(map[string]map[string][]interface{})
	all := make(map[string][]interface{})

	for _, spec := range specs {
		// b := make([]byte, 6050)
		// n, err := spec.Read(b)
		// if err != nil {
		// 	logrus.Fatalf("Failed to read b: %v", err)
		// } else {
		// 	logrus.Infof("Read %d bytes", n)
		// }

		// f, err := fabric.ParseFabricJSON(b)
		// if err != nil {
		// 	logrus.Fatalf("Failed to parse json: %v", err)
		// }
		// logrus.Infof("num paths: %d", f.Spec.Paths)
		// continue

		d := yaml.NewDecoder(spec)
		for {
			var o map[string]interface{}
			if err := d.Decode(&o); err == io.EOF || err == nil && len(o) == 0 {
				logrus.Printf("decode eof(%v) errNil(%v) len(o)=%d", err == io.EOF, err == nil, len(o))
				break
			} else if err != nil {
				println("found err:", err.Error)
				return nil, err
			}

			kind, ok := o["kind"].(string)
			if !ok {
				println("kind")
				spew.Dump(o)
				return nil, errInvalidFixture
			}

			meta, ok := o["metadata"].(map[interface{}]interface{})
			if !ok {
				println("metadata")
				spew.Dump(meta)
				return nil, errInvalidFixture
			}

			namespace, ok := meta["namespace"]
			if !ok || namespace == "" {
				namespace = "default"
			} else {
				if _, ok := namespace.(string); !ok {
					println("namespace")
					spew.Dump(meta)
					return nil, errInvalidFixture
				}
			}

			ns := namespace.(string)
			if _, ok := namespaces[ns]; !ok {
				namespaces[ns] = make(map[string][]interface{})
			}

			namespaces[ns][kind] = append(namespaces[ns][kind], o)
			all[kind] = append(all[kind], o)
			if name, ok := meta["name"]; ok {
				println("name:", name.(string), ns, kind)
			}
			println("HERE:", kind)
		}
	}

	for ns, kinds := range namespaces {
		var err error
		a.namespaces[ns], err = initNamespace(kinds)
		if err != nil {
			return nil, err
		}
	}

	a.all, err = initNamespace(all)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	println("ServeHTTP", r.URL.Path)
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if a.failOn[r.URL.Path] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if a.findNot[r.URL.Path] {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.URL.Path == kubernetes.ZalandoResourcesClusterURI {
		w.Write(a.resourceList)
		return
	}

	parts := a.pathRx.FindStringSubmatch(r.URL.Path)
	if len(parts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ns := a.all
	if parts[2] != "" {
		ns = a.namespaces[parts[2]]
	}

	var b []byte
	switch parts[3] {
	case "services":
		b = ns.services
	case "ingresses":
		b = ns.ingresses
	case "fabricgateways":
		b = ns.fabricgateways
	case "routegroups":
		b = ns.routeGroups
	case "endpoints":
		b = ns.endpoints
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Write(b)
}

func initNamespace(kinds map[string][]interface{}) (ns namespace, err error) {
	if err = itemsJSON(&ns.services, kinds["Service"]); err != nil {
		return
	}

	if err = itemsJSON(&ns.ingresses, kinds["Ingress"]); err != nil {
		return
	}

	println("kinds:", kinds, kinds["FabricGateways"])
	if err = itemsJSON(&ns.fabricgateways, kinds["FabricGateways"]); err != nil {
		return
	}

	if err = itemsJSON(&ns.routeGroups, kinds["RouteGroup"]); err != nil {
		return
	}

	if err = itemsJSON(&ns.endpoints, kinds["Endpoints"]); err != nil {
		return
	}

	return
}

func itemsJSON(b *[]byte, o []interface{}) error {
	items := map[string]interface{}{"items": o}
	println(o)

	// converting back to YAML, because we have YAMLToJSON() for bytes, and
	// the data in `o` contains YAML parser style keys of type interface{}
	y, err := yaml.Marshal(items)
	if err != nil {
		return err
	}

	*b, err = yaml2.YAMLToJSON(y)
	if err == nil {
		println(string(*b))
	}
	return err
}

func readAPIOptions(r io.Reader) (o TestAPIOptions, err error) {
	var b []byte
	b, err = io.ReadAll(r)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(b, &o)
	return
}

func mapStrings(s []string) map[string]bool {
	m := make(map[string]bool)
	for _, si := range s {
		m[si] = true
	}

	return m
}
