all: fmt vet lint test

vet:
	go vet .
	go vet ./bearer
	go vet ./revocation
	go vet ./hmacsha
	go vet ./spec
	go vet ./example

fmt:
	go fmt .
	go fmt ./bearer
	go fmt ./revocation
	go fmt ./hmacsha
	go fmt ./spec
	go fmt ./example

lint:
	golint .
	golint ./bearer
	golint ./revocation
	golint ./hmacsha
	golint ./spec
	golint ./example

test:
	go test -cover .
	go test -cover ./bearer
	go test -cover ./revocation
	go test -cover ./hmacsha
	go test -cover ./example
