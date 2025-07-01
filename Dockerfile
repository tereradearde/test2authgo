FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main ./cmd/app/

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .
COPY config ./config
COPY migrations ./migrations
COPY docs ./docs

EXPOSE 8080

CMD ["./main"] 