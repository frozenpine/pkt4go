NAME="multi-go"
VERSION=1.0.0
BUILD=`date +%FT%T%z`

PACKAGES=`go list ./... | grep -v /vendor/`
VETPACKAGES=`go list ./... | grep -v /vendor/ | grep -v /examples/`
GOFILES=`find . -name "*.go" -type f -not -path "./vendor/*"`

ifeq ($(OS), Windows_NT)
	BINARY=${NAME}.exe
else
	BINARY=${NAME}
endif

default:
	@go build -o bin/${BINARY}

linux:
	@GOOS=linux GOARCH=amd64 go build -o bin/${NAME}

win32:
	@GOOS=windows GOARCH=386 go build -o bin/${BINARY}

list:
	@echo ${PACKAGES}
	@echo ${GOFILES}

fmt:
	@gofmt -s -w ${GOFILES}

fmt-check:
	@diff=$$(gofmt -s -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Please run 'make fmt' and commit the result:"; \
		echo "$${diff}"; \
		exit 1; \
	fi;

install:
	@govendor sync -v

test:
	@go test -cpu=1,2,4 -v -tags integration ./...

vet:
	@go vet $(VETPACKAGES)

# docker:
#     @docker build -t wuxiaoxiaoshen/example:latest .

clean:
	@if [ -f ${BINARY} ] ; then rm -f bin/${BINARY} ; fi

.PHONY: default fmt fmt-check install test vet docker clean