.PHONY: build clean test

BINARY=destruct
MODULE=github.com/destruct/destruct

build:
	go build -o $(BINARY) ./cmd/destruct

clean:
	rm -f $(BINARY)
	rm -rf output/

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

run:
	go run ./cmd/destruct

help:
	@echo "DeStruct - Decompiler to C#"
	@echo ""
	@echo "Usage:"
	@echo "  make build    Build the binary"
	@echo "  make clean    Remove build artifacts"
	@echo "  make test     Run tests"
	@echo "  make vet      Run go vet"
	@echo "  make lint     Run golangci-lint"
	@echo "  make run      Run without building"
	@echo "  make help     Show this help"
