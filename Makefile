all: fmt vet lint test

test:
	go test -cover .
	go test -cover ./bearer
	go test -cover ./hmacsha
	go test -cover ./delegate
	go test -cover ./examples/server
	go test -cover ./examples/delegate

vet:
	go vet .
	go vet ./bearer
	go vet ./hmacsha
	go vet ./delegate
	go vet ./spec
	go vet ./examples/server
	go vet ./examples/delegate

fmt:
	go fmt .
	go fmt ./bearer
	go fmt ./hmacsha
	go fmt ./delegate
	go fmt ./spec
	go fmt ./examples/server
	go fmt ./examples/delegate

lint:
	golint .
	golint ./bearer
	golint ./hmacsha
	golint ./delegate
	golint ./spec
	golint ./examples/server
	golint ./examples/delegate
