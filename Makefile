SHELL := /bin/bash

GOCMD=go
GOMOD=$(GOCMD) mod
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

all:
	$(info  "completed running make file for golang project")
fmt:
	@go fmt ./...
lint:
	./script/lint.sh
tidy:
	$(GOMOD) tidy -v
test:
	$(GOTEST) ./... -coverprofile cp.out
build:
	$(GOBUILD) -o snyk-sso-membership cmd/snyk/main.go
build-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o snyk-sso-membership.exe cmd/snyk/main.go
.PHONY: install-req fmt test lint build tidy imports
