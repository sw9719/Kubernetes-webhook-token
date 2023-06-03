package tokenutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
	"tokenservice/ldaputils"
)

type tokeninfo struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
}

func decrypt() []byte {

	if _, err := os.Stat("tokenutils/meta/db"); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist

		return []byte("")
	}
	cipherText, err := ioutil.ReadFile("tokenutils/meta/db")
	if err != nil {
		log.Fatal(err)
	}

	// Reading key
	key, err := ioutil.ReadFile("tokenutils/crypt/key")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}

	return plainText
}

func encrypt(plainText []byte) {

	if _, err := os.Stat("tokenutils/meta/db"); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		f, err := os.Create("tokenutils/meta/db")
		if err != nil {
			log.Fatal("Couldn't open file")
		}
		f.Close()
	}

	// Reading key
	key, err := ioutil.ReadFile("tokenutils/crypt/key")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("nonce  err: %v", err.Error())
	}

	// Encrypt data
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Writing ciphertext file
	err = ioutil.WriteFile("tokenutils/meta/db", cipherText, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
}

func getsize(user string) int {
	data := decrypt()
	if string(data) == "" {
		return 0
	}
	var tmap map[string]tokeninfo
	json.Unmarshal(data, &tmap)
	c := 0
	for _, v := range tmap {
		if v.User == user {
			c++
		}
	}
	return c
}

func save(token string, user string, t tokeninfo) {
	tinfo := make(map[string]tokeninfo)
	json.Unmarshal(decrypt(), &tinfo)
	tinfo[token] = t
	data, err := json.Marshal(tinfo)
	if err != nil {
		log.Fatal("error: ", err)
	}
	encrypt(data)
}

func GetToken(user string) string {
	sz := getsize(user)
	fmt.Println(sz)
	if sz >= 3 {
		return "token limit reached"
	}
	salt := ldaputils.GetSalt(user)
	t := time.Now().Local().Format(time.RFC3339)
	h := sha1.New()
	h.Write([]byte(salt + t))
	tinfo := tokeninfo{Timestamp: t, User: user}
	token := hex.EncodeToString(h.Sum(nil))
	save(token, user, tinfo)
	return token
}

func IsValid(token string) (string, bool) {
	data := decrypt()
	var tmap map[string]tokeninfo
	json.Unmarshal(data, &tmap)
	tinfo, isPresent := tmap[token]
	if isPresent == false {
		return "", false
	}
	today := time.Now().Local()
	createtime, err := time.Parse(time.RFC3339, tinfo.Timestamp)
	if err != nil {
		log.Fatal("error:", err)
	}
	validity := createtime.Add(time.Minute * 5)
	if today.Compare(validity) > 0 {
		delete(tmap, token)
		data, err := json.Marshal(tmap)
		if err != nil {
			log.Fatal("err:", err)
		}
		encrypt(data)
		return "", false
	}
	return tmap[token].User, true

}
