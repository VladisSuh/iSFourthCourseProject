FROM golang:1.23.3-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -o server ./server

FROM alpine:3.15
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 6472
CMD ["./server"]
