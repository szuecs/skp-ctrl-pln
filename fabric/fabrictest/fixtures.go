package fabrictest

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/szuecs/skp-ctrl-pln/fabric"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/eskip"
)

type fixtureSet struct {
	name           string
	resources      string
	eskip          string
	api            string
	kube           string
	defaultFilters string
	error          string
	log            string
}

// TODO(sszuecs): some of these might be features we need in case we do a PR to skipper
// type kubeOptionsParser struct {
// 	EastWest                 bool               `yaml:"eastWest"`
// 	EastWestDomain           string             `yaml:"eastWestDomain"`
// 	EastWestRangeDomains     []string           `yaml:"eastWestRangeDomains"`
// 	EastWestRangePredicates  []*eskip.Predicate `yaml:"eastWestRangePredicatesAppend"`
// 	HTTPSRedirect            bool               `yaml:"httpsRedirect"`
// 	HTTPSRedirectCode        int                `yaml:"httpsRedirectCode"`
// 	BackendNameTracingTag    bool               `yaml:"backendNameTracingTag"`
// 	OnlyAllowedExternalNames bool               `yaml:"onlyAllowedExternalNames"`
// 	AllowedExternalNames     []string           `yaml:"allowedExternalNames"`
// }

func baseNoExt(n string) string {
	e := filepath.Ext(n)
	return n[:len(n)-len(e)]
}

// iterate over file names, looking for the ones with '.yaml' and '.eskip' extensions
// and same name, tolerating other files among the fixtures.
func rangeOverFixtures(t *testing.T, dir string, fs []os.FileInfo, test func(fixtureSet)) {
	// sort to ensure that the files belonging together by name are next to each other,
	// without extension
	sort.Slice(fs, func(i, j int) bool {
		ni := baseNoExt(fs[i].Name())
		nj := baseNoExt(fs[j].Name())
		return ni < nj
	})

	var empty fixtureSet
	for len(fs) > 0 {
		var fixtures fixtureSet

		fixtures.name = baseNoExt(fs[0].Name())
		namePrefix := fixtures.name + "."
		for len(fs) > 0 {
			n := fs[0].Name()
			if !strings.HasPrefix(n, namePrefix) {
				break
			}

			switch filepath.Ext(n) {
			case ".yaml":
				fixtures.resources = filepath.Join(dir, n)
			// case ".json":
			// 	fixtures.resources = filepath.Join(dir, n)
			case ".eskip":
				fixtures.eskip = filepath.Join(dir, n)
			case ".api":
				fixtures.api = filepath.Join(dir, n)
			case ".kube":
				fixtures.kube = filepath.Join(dir, n)
			case ".default-filters":
				fixtures.defaultFilters = filepath.Join(dir, n)
			case ".error":
				fixtures.error = filepath.Join(dir, n)
			case ".log":
				fixtures.log = filepath.Join(dir, n)
			}

			fs = fs[1:]
		}

		test(fixtures)
		fixtures = empty
	}
}

func matchOutput(matchFile, output string) error {
	b, err := os.ReadFile(matchFile)
	if err != nil {
		return err
	}

	exps := strings.Split(string(b), "\n")
	lines := strings.Split(output, "\n")
	for _, e := range exps {
		rx := regexp.MustCompile(e)

		var found bool
		for _, l := range lines {
			if rx.MatchString(l) {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("not matched: '%s'", e)
		}
	}

	return nil
}

func safeFileClose(t *testing.T, fd *os.File) {
	if err := fd.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}
}

func testFixture(t *testing.T, f fixtureSet) {
	// TODO(sszuecs): cleanup
	//println("f.name:", f.name, "f.resources:", f.resources, "f.api:", f.api, "f.eskip:", f.eskip)

	var resources []io.Reader
	if f.resources != "" {
		r, err := os.Open(f.resources)
		if err != nil {
			t.Fatal(err)
		}

		defer safeFileClose(t, r)
		resources = append(resources, r)
	}

	var apiOptions TestAPIOptions
	if f.api != "" {
		a, err := os.Open(f.api)
		if err != nil {
			t.Fatal(err)
		}

		defer safeFileClose(t, a)
		apiOptions, err = readAPIOptions(a)
		if err != nil {
			t.Fatal(err)
		}
	}

	a, err := NewAPI(apiOptions, resources...)
	if err != nil {
		t.Fatalf("Failed to create API: %v", err)
	}

	s := httptest.NewServer(a)
	defer s.Close()

	var logBuf bytes.Buffer
	// TODO: we should refactor the package to not use the global logger
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)
	defer func() {
		l := logBuf.String()
		if l != "" {
			t.Log("Captured logs:")
			t.Log(strings.TrimSpace(l))
		}
	}()

	o := fabric.Options{
		KubernetesURL: s.URL,

		// keep everything defaults
		// filters
		CheckEmployeeFilter:          "",
		CheckServiceFilter:           "",
		CheckEmployeeOrServiceFilter: "",
		CheckCommonScopeFilter:       "",
		LogServiceFilter:             "",
		LogUserFilter:                "",
		ForwardTokenServiceFilter:    "",
		ForwardTokenEmployeeFilter:   "",
		FlowIDFilter:                 "",
		// rest
		ClusterClientRatelimitHeader: "",
		UidKey:                       "",
		UserListPredicate:            "",
		UserRealmPredicate:           "",
	}
	c, err := fabric.NewFabricDataClient(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	routes, err := c.LoadAll()
	if f.eskip != "" {
		eskp, err := os.Open(f.eskip)
		if err != nil {
			t.Fatal(err)
		}

		defer safeFileClose(t, eskp)
		b, err := io.ReadAll(eskp)
		if err != nil {
			t.Fatal(err)
		}

		expectedRoutes, err := eskip.Parse(string(b))
		if err != nil {
			t.Fatal(err)
		}

		if len(routes) != len(expectedRoutes) {
			t.Errorf("Failed to get expected number of routes %d, got %d", len(expectedRoutes), len(routes))
		}

		sort.SliceStable(routes, func(i, j int) bool {
			return routes[i].Id < routes[j].Id
		})
		sort.SliceStable(expectedRoutes, func(i, j int) bool {
			return expectedRoutes[i].Id < expectedRoutes[j].Id
		})
		if !cmp.Equal(eskip.String(eskip.CanonicalList(routes)...), eskip.String(eskip.CanonicalList(expectedRoutes)...)) {
			t.Error("Failed to convert the resources to the right routes.")
			t.Logf("got:\n%s", eskip.String(eskip.CanonicalList(routes)...))
			t.Logf("expected:\n%s", eskip.String(eskip.CanonicalList(expectedRoutes)...))
			expectedString := eskip.Print(eskip.PrettyPrintInfo{Pretty: true}, eskip.CanonicalList(expectedRoutes)...)
			gotString := eskip.Print(eskip.PrettyPrintInfo{Pretty: true}, eskip.CanonicalList(routes)...)
			t.Logf("diff\n%s:", cmp.Diff(
				expectedString,
				gotString,
			))
			// TODO(sszuecs): cleanup
			// os.WriteFile("expected.eskip", []byte(expectedString), 0644)
			// os.WriteFile("got.eskip", []byte(gotString), 0644)
		}
	}

	if f.error == "" && err != nil {
		t.Fatalf("Test fabricgateway %s: %v", f.name, err)
	} else if f.error != "" {
		var msg string
		if err != nil {
			msg = err.Error()
		}

		if err := matchOutput(f.error, msg); err != nil {
			t.Errorf("Failed to match error: %v.", err)
		}
	}

	if f.log != "" {
		if err := matchOutput(f.log, logBuf.String()); err != nil {
			b, err := os.ReadFile(f.log)
			if err != nil {
				t.Fatal(err)
			}

			t.Errorf("Failed to match log: %v.", err)
			t.Logf("Expected: %s", string(b))
		}
	}
}

func FixturesToTest(t *testing.T, dirs ...string) {
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			dir = filepath.Join(wd, dir)
		}

		d, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer safeFileClose(t, d)

		fs, err := d.Readdir(0)
		if err != nil {
			t.Fatal(err)
		}

		rangeOverFixtures(t, dir, fs, func(f fixtureSet) {
			t.Run(f.name, func(t *testing.T) {
				testFixture(t, f)
			})
		})
	}
}
