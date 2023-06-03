package ldaputils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-ldap/ldap"
)

func setcon() *ldap.Conn {
	bindusername := "cn=Directory Manager"
	bindpassword := "test"
	con, err := ldap.DialURL(fmt.Sprintf("ldap://%s:3389", "ldap.nginx.svc.cluster.local"))
	if err != nil {
		fmt.Println("error:", err)
	}
	if err != nil {
		fmt.Println("Error during dial:", err)
		os.Exit(0)
	}

	caCert, err := ioutil.ReadFile("/home/swapnil/ldap/myca.crt")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	cfg := &tls.Config{
		ServerName: "ldap.nginx.svc.cluster.local",
		RootCAs:    caCertPool,
	}
	err = con.StartTLS(cfg)
	if err != nil {
		fmt.Println("Error during Start TLS:", err)
	}

	err = con.Bind(bindusername, bindpassword)
	if err != nil {
		fmt.Println("Error during bind:", err)
	}
	return con

}

func Auth(user string, pass string) bool {
	con := setcon()
	defer con.Close()

	searchRequest := ldap.NewSearchRequest(
		"ou=users,dc=svc,dc=cluster,dc=local",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(cn=%s))", ldap.EscapeFilter(user)),
		[]string{"dn"},
		nil,
	)

	sr, err := con.Search(searchRequest)
	if err != nil {
		fmt.Println("Error during search auth:", err)
	}

	if len(sr.Entries) != 1 {
		fmt.Println("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	err = con.Bind(userdn, pass)
	if err != nil {
		return false
	} else {
		return true
	}

}

func GetSalt(user string) string {
	con := setcon()
	defer con.Close()

	searchRequest := ldap.NewSearchRequest(
		"ou=users,dc=svc,dc=cluster,dc=local",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(cn=%s))", ldap.EscapeFilter(user)),
		[]string{"dn"},
		nil,
	)

	sr, err := con.Search(searchRequest)
	if err != nil {
		fmt.Println("Error during search:", err)
	}

	if len(sr.Entries) != 1 {
		fmt.Println("User does not exist or too many entries returned")
	}

	return sr.Entries[0].GetAttributeValue("salt")

}
