package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"tokenservice/ldaputils"
	"tokenservice/tokenutils"

	v1beta1 "k8s.io/api/authentication/v1beta1"
)

type st struct {
	Authenticated bool             `json:"authenticated"`
	Userinfo      v1beta1.UserInfo `json:"user"`
	Error         string           `json:"error"`
	Audiences     []string         `json:"audiences"`
}

type treview struct {
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     st     `json:"status"`
}

type query struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

type response struct {
	Authenticated bool   `json:"authenticated"`
	Token         string `json:"token"`
}

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World")
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		checkuser(w, r)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		validatetoken(w, r)
	})

	caCert, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8080 with the TLS config
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

	fmt.Println("Server Started On Port 8080")
	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))

	log.Fatal(err)
}

func validatetoken(w http.ResponseWriter, r *http.Request) {
	t := v1beta1.TokenReview{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	//log.Println(string(body))
	err = json.Unmarshal(body, &t)
	if err != nil {
		panic(err)
	}
	tok := t.Spec.Token
	User, valid := tokenutils.IsValid(tok)
	er := ""
	if valid == false {
		er = "Token invalid or expired"
	}
	token := treview{ApiVersion: t.APIVersion, Kind: t.Kind, Status: st{
		Authenticated: valid,
		Userinfo:      v1beta1.UserInfo{Username: User},
		Error:         er,
		Audiences:     t.Spec.Audiences,
	}}
	w.Header().Set("Content-Type", "Application/json")
	w.WriteHeader(http.StatusOK)
	res, err := json.Marshal(token)
	fmt.Println(string(res))
	if err != nil {
		fmt.Println(err)
	}
	w.Write(res)
}

func checkuser(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Error:", err)
	}
	qry := query{}
	err = json.Unmarshal(body, &qry)
	if err != nil {
		fmt.Println("Error", err)
	}
	ath := ldaputils.Auth(qry.User, qry.Pass)
	tkn := ""
	if ath == true {
		tkn = tokenutils.GetToken(qry.User)
	}
	rs := response{Authenticated: ath, Token: tkn}
	w.Header().Set("Content-Type", "Application/json")
	status := http.StatusForbidden
	if ath == true {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	res, err := json.Marshal(rs)
	if err != nil {
		fmt.Println(err)
	}
	w.Write(res)

}
