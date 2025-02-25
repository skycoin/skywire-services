.DEFAULT_GOAL := help
.PHONY : check lint lint-extra install-linters dep test
.PHONY : build  clean install  format  build-race deploy
.PHONY : integration-build
.PHONY : integration-run-generic
.PHONY : e2e-build e2e-run e2e-test e2e-stop e2e-clean

SHELL := /usr/bin/env bash

VERSION := $(shell git describe --always)

RFC_3339 := "+%Y-%m-%dT%H:%M:%SZ"
DATE := $(shell date -u $(RFC_3339))
COMMIT := $(shell git rev-list -1 HEAD)

OPTS?=GO111MODULE=on
DOCKER_OPTS?=GO111MODULE=on GOOS=linux
DOCKER_NETWORK?=SKYWIRE
DOCKER_COMPOSE_FILE:=./docker/docker-compose.yml
DOCKER_REGISTRY:=skycoin
TEST_OPTS:=-tags no_ci -cover -timeout=5m
RACE_FLAG:=-race
GOARCH:=$(shell go env GOARCH)

ifneq (,$(findstring 64,$(GOARCH)))
    TEST_OPTS:=$(TEST_OPTS) $(RACE_FLAG)
endif

BUILDINFO_VERSION := -X $(BUILDINFO_PATH).version=$(VERSION)
BUILDINFO_DATE := -X $(BUILDINFO_PATH).date=$(DATE)
BUILDINFO_COMMIT := -X $(BUILDINFO_PATH).commit=$(COMMIT)

BUILDINFO?=$(BUILDINFO_VERSION) $(BUILDINFO_DATE) $(BUILDINFO_COMMIT)

BUILD_OPTS?="-ldflags=$(BUILDINFO)"
BUILD_OPTS_DEPLOY?="-ldflags=$(BUILDINFO) -w -s"

export COMPOSE_FILE=${DOCKER_COMPOSE_FILE}
export REGISTRY=${DOCKER_REGISTRY}

## : ## _ [Prepare code]

dep: ## Sorts dependencies
#	GO111MODULE=on GOPRIVATE=github.com/skycoin/* go get -v github.com/skycoin/skywire@master
#	GO111MODULE=on GOPRIVATE=github.com/skycoin/* go mod vendor -v

format: dep ## Formats the code. Must have goimports and goimports-reviser installed (use make install-linters).
	goimports -w -local github.com/skycoin/skywire-services ./pkg ./cmd ./internal
	find . -type f -name '*.go' -not -path "./.git/*" -not -path "./vendor/*"  -exec goimports-reviser -project-name ${PROJECT_BASE} {} \;

## : ## _ [Build, install, clean]

build: dep ## Build binaries
	${OPTS} go build ${BUILD_OPTS} -o ./bin/skywire-services ./cmd/skywire-services

build-deploy: ## Build for deployment Docker images
	${DOCKER_OPTS} go build ${BUILD_OPTS_DEPLOY} -mod=vendor -o ./release/skywire-services ./cmd/skywire-services

build-race: dep ## Build binaries
	${OPTS} go build ${BUILD_OPTS} -race -o ./bin/skywire-services ./cmd/skywire-services

install: ## Install route-finder, transport-discovery, address-resolver, sw-env, keys-gen, network-monitor, node-visualizer
	${OPTS} go install ${BUILD_OPTS} ./cmd/skywire-services

clean: ## Clean compiled binaries
	rm -rf bin

## : ## _ [Test and lint]

install-linters: ## Install linters
	- VERSION=1.61.0 ./ci_scripts/install-golangci-lint.sh
	GOPRIVATE=github.com/skycoin/* go get -u github.com/FiloSottile/vendorcheck
	# For some reason this install method is not recommended, see https://github.com/golangci/golangci-lint#install
	# However, they suggest `curl ... | bash` which we should not do
	GOPRIVATE=github.com/skycoin/* go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	${OPTS} GOPRIVATE=github.com/skycoin/* go get -u github.com/incu6us/goimports-reviser

install-shellcheck: ## install shellcheck to current directory
	./ci_scripts/install-shellcheck.sh

lint: ## Run linters. Use make install-linters first.
	golangci-lint version
	${OPTS}	golangci-lint run -c .golangci.yml ./...
	${OPTS} go vet -all -mod=vendor ./...

lint-extra: ## Run linters with extra checks.
	golangci-lint run --no-config --enable-all ./...
	go vet -all -mod=vendor ./...

lint-shell:
	find ./ci_scripts -type f -iname '*.sh' -print0 | xargs -0 -I {} bash -c "./shellcheck \"{}\""
	find ./docker -type f -iname '*.sh' -print0 | xargs -0 -I {} bash -c "./shellcheck -e SC2086 \"{}\""

test: ## Run tests for net
	-go clean -testcache
	go test ${TEST_OPTS} -mod=vendor ./internal/...
	go test ${TEST_OPTS} -mod=vendor ./pkg/...

check: lint check-help test  lint-shell ## Run lint and test

check-help: ## Cursory check of the help menus
	@echo "checking help menus for compilation without errors"
	@echo
	go run cmd/skywire-services/services.go --help
	@echo
	go run cmd/skywire-services/services.go ar --help
	@echo
	go run cmd/skywire-services/services.go confbs --help
	@echo
	go run cmd/skywire-services/services.go kg --help
	@echo
	go run cmd/skywire-services/services.go nv --help
	@echo
	go run cmd/skywire-services/services.go rf --help
	@echo
	go run cmd/skywire-services/services.go se --help
	@echo
	go run cmd/skywire-services/services.go tpd --help
	@echo
	go run cmd/skywire-services/services.go tps --help
	@echo
	go run cmd/skywire-services/services.go ut --help
	@echo
	go run cmd/config-bootstrapper/config.go --help
	@echo
	go run cmd/transport-discovery/transport-discovery.go --help
	@echo
	go run cmd/keys-gen/keys-gen.go --help
	@echo
	go run cmd/sw-env/sw-env.go --help
	@echo
	go run cmd/uptime-tracker/uptime-tracker.go --help
	@echo
	go run cmd/route-finder/route-finder.go --help
	@echo
	go run cmd/setup-node/setup-node.go --help
	@echo
	go run cmd/transport-setup/transport-setup.go --help
	@echo
	go run cmd/node-visualizer/node-visualizer.go --help
	@echo
#	go run cmd/skysocks-lite-client/skysocks-lite-client.go --help
#	@echo
	go run cmd/address-resolver/address-resolver.go --help
	@echo
#	go run cmd/vpn-lite-client/vpn-lite-client.go --help
#	@echo
	go run cmd/network-monitor/network-monitor.go --help
	@echo

## : ## _ [E2E tests suite]

e2e-build: set-forwarding ## E2E. Build dockers and containers for e2e-tests
	./docker/docker_build.sh e2e ${BUILD_OPTS_DEPLOY} $(BUILD_ARCH)

e2e-run: ## E2E. Start e2e environment
	bash -c "DOCKER_TAG=e2e docker compose up -d"
	bash -c "DOCKER_TAG=e2e docker compose ps"

e2e-logs:
	bash -c "docker compose logs --tail=all --follow"

e2e-test: set-forwarding ## E2E. Run e2e-tests suite. Prepare e2e environment with `make e2e-build && make e2e-run`
	-go clean -testcache
	go test  -v -timeout=15m ./internal/integration

e2e-stop: reset-forwarding ## E2E. Stop e2e environment without destroying it. Restart with `make e2e-run`
	bash -c "DOCKER_TAG=e2e docker compose -f ${COMPOSE_FILE} stop"
	bash -c "DOCKER_TAG=e2e docker compose -f ${COMPOSE_FILE} ps"

e2e-clean: ## E2E. Stop e2e environment and clean everything. Restart only with `make e2e-build && make e2e-run`
	bash -c "DOCKER_TAG=e2e docker compose -f ${COMPOSE_FILE} down"
	bash ./docker/docker_clean.sh e2e

e2e-help: ## E2E. Show env-vars and useful commands
	@echo -e "\nNow you can use docker compose:\n"
	@echo -e "   docker compose ps/top/logs"
	@echo -e "   docker compose up/down/start/stop"
	@echo -e "\nConsult with:\n\n   docker compose help\n"

docker-build-test:
	bash ./docker/docker_build.sh test ${BUILD_OPTS_DEPLOY}

docker-build:
	bash ./docker/docker_build.sh prod ${BUILD_OPTS_DEPLOY}

docker-push-test:
	bash ./docker/docker_build.sh test ${BUILD_OPTS_DEPLOY}
	bash ./docker/docker_push.sh test

docker-push:
	bash ./docker/docker_build.sh prod ${BUILD_OPTS_DEPLOY}
	bash ./docker/docker_push.sh prod

set-forwarding:
	# following 2 lines are needed for SD to function. these can't be run from within the container and need to be run on the host machine
	if [ $(shell uname -s) == "Linux" ]; then \
		sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' && \
		sudo bash -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'; \
	fi

reset-forwarding:
	# revert the changes
	if [ $(shell uname -s) == "Linux" ]; then \
		sudo bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward' && \
		sudo bash -c 'echo 0 > /proc/sys/net/ipv6/conf/all/forwarding'; \
	fi
## : ## _ [Interactive integration tests]

integration-env-build: set-forwarding #build
	./docker/docker_build.sh integration ${BUILD_OPTS_DEPLOY} $(BUILD_ARCH)
	bash -c "DOCKER_TAG=integration docker compose up -d"

integration-env-start: set-forwarding #start
	bash -c "DOCKER_TAG=integration docker compose up -d"

integration-env-stop: reset-forwarding #stop
	bash -c "DOCKER_TAG=integration docker compose -f ${COMPOSE_FILE} stop"

integration-env-clean: #clean
	bash -c "DOCKER_TAG=integration docker compose -f ${COMPOSE_FILE} down"
	bash ./docker/docker_clean.sh integration

## : ## _ [Other]

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$|^##.*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
