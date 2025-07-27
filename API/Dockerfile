FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM alpine:latest

RUN apk --no-cache add curl

WORKDIR /root/

COPY --from=builder /app/main .
COPY wait-for-keycloak.sh .

RUN chmod +x wait-for-keycloak.sh

EXPOSE 8080

CMD ["./main"]
