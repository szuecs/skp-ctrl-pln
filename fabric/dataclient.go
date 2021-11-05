package fabric

import "github.com/zalando/skipper/eskip"

type FabricDataClient struct {
	testIn  string
	testOut string
}

func NewFabricDataClient() (*FabricDataClient, error) {
	return &FabricDataClient{
		testIn:  "",
		testOut: "",
	}, nil
}

func (fdc *FabricDataClient) Close() {}

func (fdc *FabricDataClient) LoadAll() ([]*eskip.Route, error) {
	// for all fabric resources do:
	// func ParseFabricJSON(d []byte) (*Fabric, error) {
	// and maybe
	// func validateFabricResource(fg *Fabric) error {
	return nil, nil
}

func (fdc *FabricDataClient) LoadUpdate() ([]*eskip.Route, []string, error) {
	return nil, nil, nil
}
