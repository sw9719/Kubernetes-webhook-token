FROM golang
RUN mkdir -p /app/tokenservice && mkdir /app/tokenservice/ldaputils && mkdir /app/tokenservice/tokenutils
COPY main.go go.mod go.sum server.crt server.key ca.pem  /app/tokenservice
COPY ldaputils /app/tokenservice/ldaputils/
COPY tokenutils /app/tokenservice/tokenutils/
WORKDIR /app/tokenservice
RUN go build -o main .
CMD ["/app/main"]
