FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o um-proxy main.go

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/um-proxy /um-proxy

# حصر استهلاك الذاكرة
ENV GOMEMLIMIT=15MiB
ENV GOGC=50

# القيم الافتراضية
ENV PORT=8080
ENV UM_PROTO=http
ENV UM_HOST=192.168.216.1
ENV UM_PORT=12008

EXPOSE 8080
ENTRYPOINT ["/um-proxy"]

