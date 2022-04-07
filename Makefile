SOURCES            = $(shell find . -name '*.go')
PACKAGES           = $(shell go list ./...)

deps:
	go env
	@go install honnef.co/go/tools/cmd/staticcheck@latest

fmt: $(SOURCES)
	@gofmt -w -s $(SOURCES)

check-fmt: $(SOURCES)
	@if [ "$$(gofmt -s -d $(SOURCES))" != "" ]; then false; else true; fi

staticcheck: $(SOURCES)
	staticcheck -checks "all,-ST1000,-ST1003,-ST1012,-ST1020,-ST1021" $(PACKAGES)

vet: $(SOURCES)
	go vet $(PACKAGES)

feature-check:
	go test ./fabric -run 'TestFabricFeature'
