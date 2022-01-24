SOURCES            = $(shell find . -name '*.go')
PACKAGES           = $(shell go list ./...)

deps:
	go env
	mkdir -p .bin
	@curl -o /tmp/staticcheck_linux_amd64.tar.gz -LO https://github.com/dominikh/go-tools/releases/download/2021.1.2/staticcheck_linux_amd64.tar.gz
	@sha256sum /tmp/staticcheck_linux_amd64.tar.gz | grep -q edf3b59dea0eb0e55ebe4cb3c47fdd05e25f9365771eb073a78cf66b8f093d9e
	@tar -C /tmp -xzf /tmp/staticcheck_linux_amd64.tar.gz
	@mv /tmp/staticcheck/staticcheck .bin
	@chmod +x .bin/staticcheck


fmt: $(SOURCES)
	@gofmt -w -s $(SOURCES)

check-fmt: $(SOURCES)
	@if [ "$$(gofmt -s -d $(SOURCES))" != "" ]; then false; else true; fi

staticcheck: $(SOURCES)
	.bin/staticcheck -checks "all,-ST1000,-ST1003,-ST1012,-ST1020,-ST1021" $(PACKAGES)

vet: $(SOURCES)
	go vet $(PACKAGES)

feature-check:
	go test ./fabric -run 'TestFabricFeature'
