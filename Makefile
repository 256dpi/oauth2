all: fmt vet lint test

test:
	go test -cover .
	go test -cover ./example

vet:
	go vet .
	go vet ./spec
	go vet ./example

fmt:
	go fmt .
	go fmt ./spec
	go fmt ./example

lint:
	golint .
	golint ./spec
	golint ./example
