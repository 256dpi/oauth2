all: fmt vet lint test

test:
	go test -cover .
	go test -cover ./bearer
	go test -cover ./hmacsha
	go test -cover ./flow
	go test -cover ./spec
	go test -cover ./examples/basic
	go test -cover ./examples/flow

vet:
	go vet .
	go vet ./bearer
	go vet ./hmacsha
	go vet ./flow
	go vet ./spec
	go vet ./examples/basic
	go vet ./examples/flow

fmt:
	go fmt .
	go fmt ./bearer
	go fmt ./hmacsha
	go fmt ./flow
	go fmt ./spec
	go fmt ./examples/basic
	go fmt ./examples/flow

lint:
	golint .
	golint ./bearer
	golint ./hmacsha
	golint ./flow
	golint ./spec
	golint ./examples/basic
	golint ./examples/flow
