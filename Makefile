build:
	@go build -o bin/gobank

run: build
	@./bin/gobank

run-db:
	@docker run -e POSTGRES_PASSWORD=gobank -p 5432:5432 postgres

test:
	@go test -v ./...

