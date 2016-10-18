all: fmt vet lint test

test:
	go test -cover .
	go test -cover ./bearer
	go test -cover ./examples/server

vet:
	go vet .
	go vet ./bearer
	go vet ./spec
	go vet ./examples/server

fmt:
	go fmt .
	go fmt ./bearer
	go fmt ./spec
	go fmt ./examples/server

lint:
	golint .
	golint ./bearer
	golint ./spec
	golint ./examples/server
