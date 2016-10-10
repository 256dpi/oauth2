all: fmt vet lint test

test:
	go test -cover .

vet:
	go vet .
	go vet ./example

fmt:
	go fmt .
	go fmt ./example

lint:
	golint .
	golint ./example
