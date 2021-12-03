package fabric

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type Metadata struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Created     time.Time         `json:"creationTimestamp"`
	UID         string            `json:"uid"`
	Annotations map[string]string `json:"annotations"`
}

type FabricList struct {
	Items []*Fabric `json:"items"`
}

type Fabric struct {
	Metadata *Metadata     `json:"metadata"`
	Spec     *FabricSpec   `json:"spec"`
	Status   *FabricStatus `json:"status"`
}

type FabricSpec struct {
	Paths                   *FabricPaths                   `json:"paths"`
	Admins                  []string                       `json:"x-fabric-admins"`
	Compression             *FabricCompression             `json:"x-fabric-compression-support"`
	Cors                    *FabricCorsSupport             `json:"x-fabric-cors-support"`
	EmployeeAccess          *FabricEmployeeAccess          `json:"x-fabric-employee-access"`
	Service                 []*FabricService               `json:"x-fabric-service"`
	ExternalServiceProvider *FabricExternalServiceProvider `json:"x-external-service-provider"`
	AllowList               []string                       `json:"x-fabric-whitelist"`
}

type FabricExternalServiceProvider struct {
	Hosts    []string `json:"hosts"`
	StackSet string   `json:"stackSetName"`
}

type FabricCorsSupport struct {
	AllowedHeaders []string `json:"allowedHeaders"`
	AllowedOrigins []string `json:"allowedOrigins"`
}

type FabricPaths struct {
	PathData map[string]interface{} `json:"-"`
	Path     []*FabricPath
}

func (fps *FabricPaths) UnmarshalJSON(value []byte) error {
	println("FabricPaths.UnmarshalJSON")
	if fps == nil {
		println("fps nil:", len(value))
		return nil
	}
	println("FabricPaths.UnmarshalJSON 1")

	var h map[string]interface{}
	err := json.Unmarshal(value, &h)
	if err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
		return err
	}
	println("FabricPaths.UnmarshalJSON 2")

	fps.Path = make([]*FabricPath, 0, len(h))
	for p, ve := range h {
		println("FabricPaths.UnmarshalJSON 3")
		fmes, ok := ve.(map[string]interface{})
		if !ok {
			log.Fatalf("type assertion of ve %T to 'map[string]interface{}' was not ok", ve)
			continue
		}
		fms := make([]*FabricMethod, 0, len(fmes))
		for method, fme := range fmes {
			println("FabricPaths.UnmarshalJSON 4")
			fmoes, ok := fme.(map[string]interface{})
			if !ok {
				log.Fatalf("type assertion of fme %T to 'map[string]interface{}' was not ok", fme)
				continue
			}
			println("FabricPaths.UnmarshalJSON 4.1:", len(fmoes))
			fm := FabricMethod{
				Method: method,
			}

			for k, fmoe := range fmoes {
				println("FabricPaths.UnmarshalJSON 5")

				fmt.Printf("Found '%s' for method '%s' in path '%s'\n", k, method, p)
				println("FabricPaths.UnmarshalJSON 6")
				switch k {
				case "x-fabric-privileges":
					log.Infof("Found x-fabric-privileges for method '%s' in path '%s'", method, p)
					privse, ok := fmoe.([]interface{})
					if !ok {
						log.Fatalf("type assertion privse for x-fabric-privileges was not ok: %v", fmoe)
						continue
					}
					privs := make([]string, 0, len(privse))
					for _, se := range privse {
						priv, ok := se.(string)
						if !ok {
							log.Fatalf("type assertion for x-fabric-privileges was not ok: %v", se)
							continue
						}
						privs = append(privs, priv)
					}
					fm.Privileges = privs

				case "x-fabric-ratelimits":
					limitse, ok := fmoe.(map[string]interface{})
					if !ok {
						log.Fatalf("type assertion of fme %T to 'map[string]interface{}' was not ok", fmoe)
						continue
					}
					fr := FabricRatelimit{}
					for limitKey, limitVal := range limitse {
						switch limitKey {
						case "default-rate":
							l, ok := limitVal.(float64)
							if !ok {
								log.Fatalf("type assertion of limitVal '%s' to int was not ok", limitVal)
								continue
							}
							fr.DefaultRate = int(l)

						case "period":
							s, ok := limitVal.(string)
							if !ok {
								log.Fatalf("type assertion of limitVal '%v' to string was not ok", limitVal)
								continue
							}

							var d time.Duration
							switch s {
							case "second":
								d = time.Second
							case "minute":
								d = time.Minute
							case "hour":
								d = time.Hour
							default:
								log.Fatalf("period %s not found", s)
							}
							fr.Period = d

						case "target":
							h, ok := limitVal.(map[string]interface{})
							if !ok {
								log.Fatalf("type assertion target of limitVal '%s' to map[string]interface{} was not ok", limitVal)
								continue
							}

							fts := make([]*FabricTarget, 0, len(h))
							for uid, v := range h {
								rate, ok := v.(float64)
								if !ok {
									log.Fatalf("type rate of v '%s' to float64 was not ok", v)
									continue
								}
								ft := FabricTarget{
									UID:  uid,
									Rate: int(rate),
								}
								fts = append(fts, &ft)
							}
							fr.Target = fts

						default:
							log.Fatalf("Unknown limitkey: '%s', val: %v", limitKey, limitVal)
						}
					}
					fm.Ratelimit = &fr

				case "x-fabric-static-response":
					var response FabricResponse
					staticResponseMap, ok := fmoe.(map[string]interface{})
					if !ok {
						log.Fatalf("type assertion of x-fabric-static-response '%v' to map[string]interface{} was not ok", fmoe)
						continue
					}
					for staticKey, staticVal := range staticResponseMap {
						// log.Printf("%s: %T %v", staticKey, staticVal, staticVal)
						switch staticKey {
						case "body":
							staticStr, ok := staticVal.(string)
							if !ok {
								log.Fatalf("type assertion of staticVal '%v' to string was not ok", staticVal)
								continue
							}
							var fr FabricResponse
							json.Unmarshal([]byte(staticStr), &fr)

						case "headers":
							response.Headers = make(map[string]string)
							staticMap, ok := staticVal.(map[string]interface{})
							if !ok {
								log.Fatalf("type assertion of staticVal %T headers '%v' to map[string]interafce{} was not ok", staticVal, staticVal)
								continue
							}
							for k, v := range staticMap {
								response.Headers[k], ok = v.(string)
							}
						case "status":
							l, ok := staticVal.(float64)
							if !ok {
								log.Fatalf("type assertion of staticVal status '%v' to float64 was not ok", staticVal)
							}
							response.StatusCode = int(l)
						default:
							log.Fatalf("Unknown key '%s' for FabricResponse", staticKey)
						}
					}
					fm.Response = &response

				case "x-fabric-employee-access":
					fabEmployeeAccess, ok := fmoe.(map[string]interface{})
					if !ok {
						log.Fatalf("type assertion of x-fabric-employee-access '%v' to map[string]interface{} was not ok", fmoe)
						continue
					}

					var fabea FabricEmployeeAccess
					for k, v := range fabEmployeeAccess {
						switch k {
						case "type":
							s, ok := v.(string)
							if !ok {
								log.Fatalf("type assertion of FabricEmployeeAccess type '%v' to string was not ok", v)
							}
							if s != "allow_list" && s != "allow_all" && s != "deny_all" {
								log.Warnf("Wrong x-fabric-employee-access %s", s)
								continue
							}
							fabea.Type = s
						case "user-list":
							ule, ok := v.([]interface{})
							if !ok {
								log.Fatalf("type assertion ule for user-list was not ok: %v", v)
								continue
							}
							userList := make([]string, 0, len(ule))
							for _, ue := range ule {
								u, ok := ue.(string)
								if !ok {
									log.Fatalf("type assertion of ue to string was not ok: %v", ue)
									continue
								}
								userList = append(userList, u)
							}
							fabea.UserList = userList
						default:
							log.Fatalf("x-fabric-employee-access key: %s is not known: %v", k, v)
						}
					}
					fm.EmployeeAccess = &fabea

				case "x-fabric-whitelist":
					fale, ok := fmoe.(map[string]interface{})
					if !ok {
						log.Fatalf("type assertion of x-fabric-whitelist '%v' to map[string]interface{} was not ok", fmoe)
						continue
					}

					var fal = FabricAllowList{
						State: "enabled",
					}
					for k, v := range fale {
						switch k {
						case "service-list":
							sle, ok := v.([]interface{})
							if !ok {
								log.Fatalf("type assertion sle for service-list was not ok: %v", v)
								continue
							}
							uids := make([]string, 0, len(fale))
							for _, se := range sle {
								uid, ok := se.(string)
								if !ok {
									log.Fatalf("type assertion of se to string was not ok: %v", se)
									continue
								}
								uids = append(uids, uid)
							}
							fal.UIDs = uids
						case "state":
							s, ok := v.(string)
							if !ok {
								log.Fatalf("type assertion state v to string was not ok: %v", v)
								continue
							}
							fal.State = s
						}
					}
					fm.AllowList = &fal

				default:
					log.Warnf("Unknown FabricMethod member: '%s' for %v", k, fmoe)
				}

			}
			// validation
			if err := validateMethod(&fm); err != nil {
				return fmt.Errorf("invalid method '%s' for path '%s': %w", fm.Method, p, err)
			}

			fms = append(fms, &fm)
		}

		if len(fms) == 0 {
			println("len(fms) is 0")
			return fmt.Errorf("invalid number of methods %d for path %s, min required 1", len(fms), p)
		}
		if len(p) == 0 {
			println("len(p) is 0")
			return fmt.Errorf("invalid path, min length required 1")
		}

		fp := FabricPath{
			Path:    p,
			Methods: fms,
		}
		fps.Path = append(fps.Path, &fp)
		println("found path:", p)
	}

	if len(fps.Path) == 0 {
		return fmt.Errorf("invalid number of paths 0, min required 1")
	}

	return nil
}

func validateEmployeeAccess(ea *FabricEmployeeAccess) error {
	if ea != nil {
		switch ea.Type {
		case "allow_list":
			if len(ea.UserList) == 0 {
				return fmt.Errorf("invalid x-fabric-employee-access user-list has no entry")
			}
		case "allow_all", "deny_all":
		default:
			return fmt.Errorf("invalid x-fabric-employee-access unknown type: '%s'", ea.Type)
		}
	}
	return nil
}

func validateMethod(fm *FabricMethod) error {
	spew.Dump(fm)
	if err := validateEmployeeAccess(fm.EmployeeAccess); err != nil {
		return err
	}

	if n := len(fm.Privileges); n == 0 {
		return fmt.Errorf("invalid number of x-fabric-privileges %d", n)
	}

	if fm.Ratelimit != nil {
		if fm.Ratelimit.DefaultRate < 1 {
			return fmt.Errorf("invalid x-fabric-ratelimits with default %d", fm.Ratelimit.DefaultRate)
		}
	}

	if fm.Response != nil && (fm.Response.StatusCode < 100 || fm.Response.StatusCode > 599) {
		return fmt.Errorf("invalid x-fabric-static-response with HTTP status code %d", fm.Response.StatusCode)
	}

	if fm.AllowList != nil {
		if s := fm.AllowList.State; s != "enabled" && s != "disabled" {
			return fmt.Errorf("invalid x-fabric-whitelist state: %s", s)
		}
		if len(fm.AllowList.UIDs) == 0 {
			return fmt.Errorf("invalid x-fabric-whitelist has to have a service-list: %d", len(fm.AllowList.UIDs))
		}
	}

	switch fm.Method {
	case "get", "head", "put", "post", "patch", "delete":
	default:
		return fmt.Errorf("invalid method '%s', required resource with valid values get, head, put, post, patch, delete", fm.Method)
	}

	return nil
}

func (fps FabricPaths) String() string {
	var sb strings.Builder
	for _, fp := range fps.Path {
		sb.WriteString(fp.Path)
		sb.WriteString(", ")
	}

	return sb.String()
}

type FabricPath struct {
	Path    string
	Methods []*FabricMethod
}

func (fp FabricPath) String() string {
	return fp.Path
}

type FabricMethod struct {
	Method         string
	EmployeeAccess *FabricEmployeeAccess `json:"x-fabric-employee-access"`
	Privileges     []string              `json:"x-fabric-privileges"`
	Ratelimit      *FabricRatelimit      `json:"x-fabric-ratelimits"`
	Response       *FabricResponse       `json:"x-fabric-static-response"`
	AllowList      *FabricAllowList      `json:"x-fabric-whitelist"`
}

type FabricAllowList struct {
	State string
	UIDs  []string
}

type FabricResponse struct {
	Title      string            `json:"title"`
	StatusCode int               `json:"status"`
	Headers    map[string]string `json:"headers"`
}

type FabricRatelimit struct {
	DefaultRate int             `json:"default-rate"`
	Period      time.Duration   `json:"period"`
	Target      []*FabricTarget `json:"target"`
}

type FabricTarget struct {
	//Key  string // default "uid" and right now the only value
	UID  string
	Rate int
}

type FabricCompression struct {
	Factor   int    `json:"compressionFactor"` // TODO(sszuecs): maybe limit to 0..9
	Encoding string `json:"encoding"`
}

type FabricEmployeeAccess struct {
	Type     string   `json:"type"` // <allow_list|allow_all|deny_all> if allow_list-> user-list must be populated, otherwise scope uid with realm /employee
	UserList []string `json:"user-list"`
}

type FabricService struct {
	Host        string `json:"host"`
	ServiceName string `json:"serviceName"` // not ing V1 compliant
	ServicePort string `json:"servicePort"` // not ing V1 compliant
}

type FabricStatus struct {
	NumberOfOwnedIngress int      `json:"num_owned_ingress"`
	ObservedGeneration   int      `json:"observedGeneration"`
	OwnedIngressNames    []string `json:"owned_ingress_names"`
}

func ParseFabricJSON(b []byte) (*Fabric, error) {
	var fg Fabric
	err := json.Unmarshal(b, &fg)
	//println("b:", string(b))
	if err != nil {
		println("ParseFabricJSON err:", err.Error())
		return nil, err
	}
	println("before validate:", fg.Spec)
	err = validateFabricResource(&fg)
	if err != nil {
		println("validation error:", err.Error())
		return nil, fmt.Errorf("invalid fabric resource: %w", err)
		//return nil, fmt.Errorf("invalid fabric resource %s/%s: %w", fg.Metadata.Namespace, fg.Metadata.Name, err)
	}

	return &fg, nil
}

func validateFabricResource(fg *Fabric) error {
	if fg == nil || fg.Spec == nil || fg.Spec.Paths == nil || len(fg.Spec.Paths.Path) == 0 {
		return fmt.Errorf("something nil: %v %v", fg, fg.Spec)
	}
	if esp := fg.Spec.ExternalServiceProvider; esp != nil {
		if len(esp.Hosts) == 0 {
			return fmt.Errorf("invalid x-external-service-provider number of hosts 0 for in fabric %s/%s", fg.Metadata.Namespace, fg.Metadata.Name)
		}
		if esp.StackSet == "" {
			return fmt.Errorf("invalid x-external-service-provider without stackset in fabric %s/%s", fg.Metadata.Namespace, fg.Metadata.Name)
		}
	}

	if comp := fg.Spec.Compression; comp != nil {
		if f := comp.Factor; f < 0 || f > 9 {
			return fmt.Errorf("invalid x-fabric-compression-support factor %d, should be 0 >= %d >= 9", f, f)
		}
		if comp.Encoding == "" {
			return fmt.Errorf("invalid x-fabric-compression-support empty encoding")
		}
	}

	if cors := fg.Spec.Cors; cors != nil {
		if len(cors.AllowedHeaders) == 0 {
			return fmt.Errorf("invalid x-fabric-cors-support requires allowed headers to be set")
		}
		if len(cors.AllowedOrigins) == 0 {
			return fmt.Errorf("invalid x-fabric-cors-support requires allowed origins to be set")
		}
		for _, s := range cors.AllowedOrigins {
			if s == "" || s == "*" {
				return fmt.Errorf("invalid x-fabric-cors-support allowed origin '%s'", s)
			}
		}
	}

	if err := validateEmployeeAccess(fg.Spec.EmployeeAccess); err != nil {
		return err
	}

	if svcs := fg.Spec.Service; len(svcs) != 0 {
		for _, svc := range svcs {
			if svc.ServiceName == "" {
				return fmt.Errorf("invalid x-fabric-service required serviceName is empty")
			}
			if svc.Host == "" {
				return fmt.Errorf("invalid x-fabric-service required host is empty for service %s/%s", svc.ServiceName, svc.ServicePort)
			}
		}
	}

	// nothing to do for: x-fabric-whitelist

	if len(fg.Spec.Paths.Path) == 0 {
		return fmt.Errorf("invalid number of paths 0")
	}

	return nil
}
