all: fmt vet lint test

test:
	go test -cover .
	go test -cover ./examples/server

vet:
	go vet .
	go vet ./spec
	go vet ./examples/server

fmt:
	go fmt .
	go fmt ./spec
	go fmt ./examples/server

lint:
	golint .
	golint ./spec
	golint ./examples/server
