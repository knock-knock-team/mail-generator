FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY backend/go.mod ./backend/go.mod
COPY backend/main.go ./backend/main.go

WORKDIR /app/backend
RUN go mod download
RUN go build -o /app/server .

FROM alpine:3.20

WORKDIR /app
COPY --from=builder /app/server /app/server
COPY frontend /app/frontend

EXPOSE 8080
CMD ["/app/server"]
