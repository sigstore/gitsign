#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GIT_VERSION ?= $(shell git describe --tags --always --dirty)

ARCH ?= $(shell uname -m)

CGO_FLAG=0
# Fix `-buildmode=pie requires external (cgo) linking, but cgo is not enabled`
ifeq ($(ARCH),riscv64)
    CGO_FLAG=1
endif

LDFLAGS=-buildid= -X github.com/sigstore/gitsign/pkg/version.gitVersion=$(GIT_VERSION)

.PHONY: build-gitsign
build-gitsign:
	CGO_ENABLED=$(CGO_FLAG) go build -trimpath -ldflags "$(LDFLAGS)" .

.PHONY: build-credential-cache
build-credential-cache:
	CGO_ENABLED=$(CGO_FLAG) go build -trimpath -ldflags "$(LDFLAGS)" ./cmd/gitsign-credential-cache

.PHONY: build-all
build-all: build-gitsign build-credential-cache

.PHONY: install-gitsign
install-gitsign:
	CGO_ENABLED=$(CGO_FLAG) go install -trimpath -ldflags "$(LDFLAGS)" github.com/sigstore/gitsign

.PHONY: install-credential-cache
install-credential-cache:
	CGO_ENABLED=$(CGO_FLAG) go install -trimpath -ldflags "$(LDFLAGS)" github.com/sigstore/gitsign/cmd/gitsign-credential-cache

.PHONY: install-all
install-all: install-gitsign install-credential-cache

.PHONY: unit-test
unit-test:
	go test -v ./...

.PHONY: proto
proto:
	@hack/generate-proto.sh

# These tests use live dependencies, and may otherwise modify state.
.PHONY: e2e-test
e2e-test:
	go test -tags e2e -v ./e2e
