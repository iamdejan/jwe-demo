.PHONY: vendor
vendor:
	go mod tidy && go mod vendor

.PHONY: run
run:
	go run main.go
