package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)


var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7ET/NF14Ml+2U
N8iT5r0C6vAoc/QqRKQYwlrM88QjUvmW3b1k3Fz3wTk1dwpBDEHFNwvwjpbHZa7Q
V4uCB7FcjzaWH6sF7DqCCWOnp5oQBWOj0fsn5EKF/b7nYez6tN3ewMf9hvd80EDj
bkI3HTPoYLLqev5ZKobe8tjRMGhJWCTUyClNvpl5tE2z0bKEna62z295GNtUum3j
JWZN4RSJljH/mOwq4JOE1CtRUnVwL+vglQJKcsjVwDTb/GHgdZHT8dYuFeeMyTMB
BW+hYhb9pz1rxBCy/Yub4LaMw2b57Ni+EBCTPID6pwldB14fy/KDCptWD95FznUa
eG7HLD7pAgMBAAECggEACjCsWw20z9bO2E4ZnQTqsuf9YRa/7DWFAtxDefqlao8w
jWlS0dW3Mr/Rz/nGEzkJtCaFffsmd4IwfaTnMpQcs0AR5yeed1og7ch5Jz7YA5tn
jBr6JXgnr4jdB1msQRPtKh8yRbs+bAwkHL961+m9VCFAXcmJZW4NnsN30B1k8OnG
XRPozkO7BWmacuStJPp1kcRGVE4l4HVJWst5xQROalNjykXah0vfN/xB3FJf0R5r
tRldVO2dQaqJYeratQhytX3CVOHeA3GF0yoFANWnJ4JPIuUZ+hNP0NyZosmarqL6
PZQfs3HUFy3t5jtQmy5s67b+IpxRqtXxQkVOB/aQaQKBgQDs8Q97cbZsjgh+TedC
F3F2EcMgOX9GxNNaE07gNIv5ZbMXGCaycEB7dGd+PEOBmTFcw6aic0y2gO2FgZ8O
dmcCAPWzTW6NM4k1QAsxbQ84BFLJbeH2wuWg0oxLkgYRKkpV+4XiYj8TEkmldRKa
+JfUrdmsHEUAXBhbn1FGB3ZInwKBgQDKHTZSNA0/DXkM43f9SX1/6C24C4FUaT1t
ldZ7vNKjDfVPj/y1jyQk+2E2uK5HfQ39JghyCI9To0mAtbRV3EcWNejJoD68yEnL
y5n/eEGpZVyU5DHHY3O2SILZdGl5XH68qSD2uEQq3AeMoARVsKq3IslBJUBORPPn
1+dRGgVjdwKBgQCPHXfNhzy5yvykVafGiuR0fXwPncsb0s0aTilJUVPuuxf2bhcJ
lrXMG95bKElaIU7oiiC/ZMdEQRG2nzmUgb3sPuopeC67SRKqQFnCa+5SVoIuuplO
9B/BCQvGpZfWjGXEE52lxNP2UAh90P4A7wC+bJfa1mRzOC1aQhvUIbO3XwKBgQCv
TulIIgf/UeNWb5MrKmxl3nCRe8FBA0uZ2ubAS0b00W2fBkhu/uqd/UEUItpf/bN9
iVi3+H7BUBe4QWNbOgaa2EXDZXAldSC1WTOJKLjjgpzsNIaM6NF8IacFkPjPoI/5
ekWyWqAeAN23dzBrVyKsWMrx66q8eQiKZ3YnnYdg/wKBgCkiHWfEXLJjbCt+pBN6
Tbxjh29J4rNUXiI6fbZSGFbjDeSJTEGEjON4mZJcZirpm54E/TCUvtQDEiABbkgV
vvJaW4+irj2Pk8xkXNY6M5pqi1Bcr9fHv0zQiezLPBbXJ9QaQIB9tTdXWRU0Qoui
83JmVeGqxCcKlQZ8cpCYWUDp
-----END PRIVATE KEY-----`

var cert = `-----BEGIN CERTIFICATE-----
MIIEXDCCAkSgAwIBAgIFANYS8o4wDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBhMC
VUsxDzANBgNVBAgMBkxvbmRvbjEQMA4GA1UECgwHUmV2b2x1dDEQMA4GA1UECwwH
U2FuZGJveDAeFw0yMTAzMTkxNzQzMDZaFw0yMjAzMTkxNzQzMDZaMIGcMQswCQYD
VQQGEwJHQjEUMBIGA1UECgwLT3BlbkJhbmtpbmcxGzAZBgNVBAsMEjAwMTU4MDAw
MDEwM1VBdkFBTTEfMB0GA1UEAwwWMmtpWFF5bzB0ZWRqVzJzb21qU2dINzE5MDcG
A1UEYQwwUFNEVUstUkVWQ0EtYWQyNWI0YTAtMDdmMS00ZWVhLWJiY2QtYWFiY2M2
MTkyMTQ3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuxE/zRdeDJft
lDfIk+a9AurwKHP0KkSkGMJazPPEI1L5lt29ZNxc98E5NXcKQQxBxTcL8I6Wx2Wu
0FeLggexXI82lh+rBew6ggljp6eaEAVjo9H7J+RChf2+52Hs+rTd3sDH/Yb3fNBA
425CNx0z6GCy6nr+WSqG3vLY0TBoSVgk1MgpTb6ZebRNs9GyhJ2uts9veRjbVLpt
4yVmTeEUiZYx/5jsKuCThNQrUVJ1cC/r4JUCSnLI1cA02/xh4HWR0/HWLhXnjMkz
AQVvoWIW/ac9a8QQsv2Lm+C2jMNm+ezYvhAQkzyA+qcJXQdeH8vygwqbVg/eRc51
Gnhuxyw+6QIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQB1MKsIMGc1fjf0jEbiXO9P
NONkP811X3OSV0ykEvrn31B3lU7cazMzkBgu85SWgnV5MfXguMtyHlh3WVFdO+Sp
dZg6ooMfL+4c0yeWGEf6SC94opJC2dXbWVPC591vFSP2yiE7fTcwjKzhMVUnIcNv
GLG6y2knZwGY7mLuAQQTXY2mCeiUd4e5jCh/CraIQWcoMyAsTZzt5IcmGV7Tv8uH
jLjOJCJbX6wrOQ3Jcs1OVuoYo5LrCcpLUS5dY/vHJMnNUn1mh1WkQUzxci80pMel
rvIXTfOSlIoCV88cRFxHMX4QxX20fqu5atVFZ+gzhX0PVTQZE7BgH60t36XGb2Ei
oYTg8keSyHw2HZcFA09wg0tr/LUj5US5r6abmdQQx9HBse45IAp1RH3UvIUalO+g
TrsEx82E3KzZjuIqRM0xcCHnt+2ykXqKCLIxqczypQby+9+R2c3MrJslB/4qFuNn
c6CwWCymb+/JP06qPjtYpCo4/Qeq+wUWkdE0n2aGRmyhgNkdFA59DL4mC2MkcZmG
LkkJer7Sny8TrCQWuU8qAs5brGxgnxHGonggdYwLmIzhuiux/VEvH3x1G6KH8AUS
4STM2T/+8MhRoPCiWjpfVtlL6tuuIW0YTRjQsg9K+uvqc4JI0UC+bYpmwAhNeTVj
+TqJebTfMwUvc6sHJgq+gA==
-----END CERTIFICATE-----`
var acMutex = &sync.Mutex{}
var GlobalAccessToken string

func hello(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "free text\n")
}


func main() {


	//sig, err := SimpleSign()
	//if err!=nil{
	//	panic(err)
	//}
	//
	//fmt.Println(sig)

	//signature, err := SignPayload(GeneratePayload("6.99"))
	//if err!=nil{panic(err)}
	//
	//fmt.Println(signature)

	http.HandleFunc("/hello", hello)
	http.HandleFunc("/jwks", jwks)
	http.HandleFunc("/payment", payment)

	http.ListenAndServe(":8080", nil)
}

func jwks(w http.ResponseWriter, req *http.Request) {
	jwks := `{"keys": [{
  "kty": "RSA",
  "e": "AQAB",
  "kid": "7c992d92-41ae-4c26-a393-54aa9c9310c9",
  "n": "uxE_zRdeDJftlDfIk-a9AurwKHP0KkSkGMJazPPEI1L5lt29ZNxc98E5NXcKQQxBxTcL8I6Wx2Wu0FeLggexXI82lh-rBew6ggljp6eaEAVjo9H7J-RChf2-52Hs-rTd3sDH_Yb3fNBA425CNx0z6GCy6nr-WSqG3vLY0TBoSVgk1MgpTb6ZebRNs9GyhJ2uts9veRjbVLpt4yVmTeEUiZYx_5jsKuCThNQrUVJ1cC_r4JUCSnLI1cA02_xh4HWR0_HWLhXnjMkzAQVvoWIW_ac9a8QQsv2Lm-C2jMNm-ezYvhAQkzyA-qcJXQdeH8vygwqbVg_eRc51Gnhuxyw-6Q",
  "use": "sig",
  "x5c": ["MIIEXDCCAkSgAwIBAgIFANYS8o4wDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEQMA4GA1UECgwHUmV2b2x1dDEQMA4GA1UECwwHU2FuZGJveDAeFw0yMTAzMTkxNzQzMDZaFw0yMjAzMTkxNzQzMDZaMIGcMQswCQYDVQQGEwJHQjEUMBIGA1UECgwLT3BlbkJhbmtpbmcxGzAZBgNVBAsMEjAwMTU4MDAwMDEwM1VBdkFBTTEfMB0GA1UEAwwWMmtpWFF5bzB0ZWRqVzJzb21qU2dINzE5MDcGA1UEYQwwUFNEVUstUkVWQ0EtYWQyNWI0YTAtMDdmMS00ZWVhLWJiY2QtYWFiY2M2MTkyMTQ3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuxE/zRdeDJftlDfIk+a9AurwKHP0KkSkGMJazPPEI1L5lt29ZNxc98E5NXcKQQxBxTcL8I6Wx2Wu0FeLggexXI82lh+rBew6ggljp6eaEAVjo9H7J+RChf2+52Hs+rTd3sDH/Yb3fNBA425CNx0z6GCy6nr+WSqG3vLY0TBoSVgk1MgpTb6ZebRNs9GyhJ2uts9veRjbVLpt4yVmTeEUiZYx/5jsKuCThNQrUVJ1cC/r4JUCSnLI1cA02/xh4HWR0/HWLhXnjMkzAQVvoWIW/ac9a8QQsv2Lm+C2jMNm+ezYvhAQkzyA+qcJXQdeH8vygwqbVg/eRc51Gnhuxyw+6QIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQB1MKsIMGc1fjf0jEbiXO9PNONkP811X3OSV0ykEvrn31B3lU7cazMzkBgu85SWgnV5MfXguMtyHlh3WVFdO+SpdZg6ooMfL+4c0yeWGEf6SC94opJC2dXbWVPC591vFSP2yiE7fTcwjKzhMVUnIcNvGLG6y2knZwGY7mLuAQQTXY2mCeiUd4e5jCh/CraIQWcoMyAsTZzt5IcmGV7Tv8uHjLjOJCJbX6wrOQ3Jcs1OVuoYo5LrCcpLUS5dY/vHJMnNUn1mh1WkQUzxci80pMelrvIXTfOSlIoCV88cRFxHMX4QxX20fqu5atVFZ+gzhX0PVTQZE7BgH60t36XGb2EioYTg8keSyHw2HZcFA09wg0tr/LUj5US5r6abmdQQx9HBse45IAp1RH3UvIUalO+gTrsEx82E3KzZjuIqRM0xcCHnt+2ykXqKCLIxqczypQby+9+R2c3MrJslB/4qFuNnc6CwWCymb+/JP06qPjtYpCo4/Qeq+wUWkdE0n2aGRmyhgNkdFA59DL4mC2MkcZmGLkkJer7Sny8TrCQWuU8qAs5brGxgnxHGonggdYwLmIzhuiux/VEvH3x1G6KH8AUS4STM2T/+8MhRoPCiWjpfVtlL6tuuIW0YTRjQsg9K+uvqc4JI0UC+bYpmwAhNeTVj+TqJebTfMwUvc6sHJgq+gA=="]
}]}`
	fmt.Fprint(w, jwks)
}


type ConsentResp struct {
	Data struct {
		Status               string    `json:"Status"`
		Statusupdatedatetime time.Time `json:"StatusUpdateDateTime"`
		Creationdatetime     time.Time `json:"CreationDateTime"`
		Consentid            string    `json:"ConsentId"`
		Initiation           struct {
			Instructionidentification string `json:"InstructionIdentification"`
			Endtoendidentification    string `json:"EndToEndIdentification"`
			Instructedamount          struct {
				Amount   string `json:"Amount"`
				Currency string `json:"Currency"`
			} `json:"InstructedAmount"`
			Creditoraccount struct {
				Schemename     string `json:"SchemeName"`
				Identification string `json:"Identification"`
				Name           string `json:"Name"`
			} `json:"CreditorAccount"`
			Remittanceinformation struct {
				Reference    string `json:"Reference"`
				Unstructured string `json:"Unstructured"`
			} `json:"RemittanceInformation"`
		} `json:"Initiation"`
	} `json:"Data"`
	Risk struct {
		Paymentcontextcode             string `json:"PaymentContextCode"`
		Merchantcategorycode           string `json:"MerchantCategoryCode"`
		Merchantcustomeridentification string `json:"MerchantCustomerIdentification"`
		Deliveryaddress                struct {
			Addressline    []string `json:"AddressLine"`
			Streetname     string   `json:"StreetName"`
			Buildingnumber string   `json:"BuildingNumber"`
			Postcode       string   `json:"PostCode"`
			Townname       string   `json:"TownName"`
			Country        string   `json:"Country"`
		} `json:"DeliveryAddress"`
	} `json:"Risk"`
	Links struct {
		Self string `json:"Self"`
	} `json:"Links"`
	Meta struct {
		Totalpages int `json:"TotalPages"`
	} `json:"Meta"`
}
func payment(w http.ResponseWriter, req *http.Request) {
	ar, err := GetAccessCode()
	if err != nil {
		panic(err)
	}
	acMutex.Lock()
	GlobalAccessToken = ar.AccessToken
	acMutex.Unlock()

	payload := GeneratePayload("6.99")
	signature, err := SignPayload(payload)
	if err != nil {
		panic(err)
	}
	fmt.Println(signature)

	body := strings.NewReader(payload)

	consentReq, err := http.NewRequest("POST", "https://sandbox-oba.revolut.com/domestic-payment-consents", body)
	if err != nil {
		panic(err)
	}

	rand.Seed(time.Now().Unix())
	n := rand.Intn(9999)
	consentReq.Header.Set("x-fapi-financial-id", "001580000103UAvAAM")
	consentReq.Header.Set("Content-Type", "application/json")
	consentReq.Header.Set("x-idempotency-Key", fmt.Sprintf("%d", n))
	consentReq.Header.Set("authorization", fmt.Sprintf("Bearer %s", ar.AccessToken))
	consentReq.Header.Set("x-jws-Signature", signature)

	resp, err := http.DefaultClient.Do(consentReq)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	respB, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(respB))

	cResp := ConsentResp{}

	err = json.Unmarshal(respB, &cResp)
	if err!=nil{
		panic(err)
	}

	//creating jwt url parameter
}

type AccessResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}


//func SimpleSign()(string, error){
//	keyBytes, err := ioutil.ReadFile("private.key")
//	if err != nil {
//		return "", err
//	}
//	block, _ := pem.Decode(keyBytes)
//	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
//	if err != nil {
//		return "", err
//	}
//
//	sign, err := jws.Sign([]byte(`{"abc": "bcd"}`), jwa.PS256, key)
//	return string(sign), err
//
//}

//func JWTParameter() (string, error){
//
//}

func SignPayload(payload string) (string, error) {

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.PS256)
	headers.Set(jws.KeyIDKey, "7c992d92-41ae-4c26-a393-54aa9c9310c9")
	headers.Set(jws.CriticalKey, []string{"http://openbanking.org.uk/tan"})
	headers.Set("http://openbanking.org.uk/tan", "openbanking-demo-1.tymurkhr.repl.co")


	block, _ := pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	sign, err := jws.Sign([]byte(payload), jwa.PS256, key, jws.WithHeaders(headers))
	if err != nil {
		return "", err

	}
	fmt.Println(string(sign))
	fmt.Println()

	rkey,ok  := key.(*rsa.PrivateKey)
	if !ok{
		panic("not rsa")
	}


	_, err = jws.Verify(sign, jwa.PS256, &rkey.PublicKey)
	if err!=nil{
		panic(err)
	}else{
		fmt.Println("all good")
	}


	toks := strings.Split(string(sign), ".")
	if len(toks) != 3 {
		return "", fmt.Errorf("invalid signature format")
	}

	return toks[0] + "." + "." + toks[2], nil
}

func GetAccessCode() (*AccessResp, error) {

	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	// curl -k --cert transport.pem --key private.key \
	// --location --request POST 'https://sandbox-oba-auth.revolut.com/token' \
	// --header 'Content-Type: application/x-www-form-urlencoded' \
	// --data-urlencode 'grant_type=client_credentials' \
	// --data-urlencode 'scope=payments'

	// TODO: This is insecure; use only in dev environments.
	cert, err := tls.X509KeyPair([]byte(cert), []byte(privateKey))
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert}},
	}
	client := &http.Client{Transport: tr}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "payments")

	req, err := http.NewRequest("POST", "https://sandbox-oba-auth.revolut.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		// handle err
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		// handle err
		panic(err)
	}
	defer resp.Body.Close()
	respBytes, _ := ioutil.ReadAll(resp.Body)
	var ar AccessResp
	err = json.Unmarshal(respBytes, &ar)
	if err != nil {
		return nil, err
	}
	return &ar, nil

}

func GeneratePayload(value string) string {
	return fmt.Sprintf(`{
	"Data": {
		"Initiation": {
			"InstructionIdentification": "ID412",
				"EndToEndIdentification": "E2E123",
				"InstructedAmount": {
				"Amount": "%s",
					"Currency": "EUR"
			},
			"CreditorAccount": {
				"SchemeName": "UK.OBIE.SortCodeAccountNumber",
					"Identification": "11223321325698",
					"Name": "Receiver Co."
			},
			"RemittanceInformation": {
				"Reference": "ReceiverRef",
					"Unstructured": "Shipment fee"
			}
		}
	},
	"Risk": {
		"PaymentContextCode": "EcommerceGoods",
			"MerchantCategoryCode": "5967",
			"MerchantCustomerIdentification": "1238808123123",
			"DeliveryAddress": {
			"AddressLine": ["7"],
				"StreetName": "Apple Street",
				"BuildingNumber": "1",
				"PostCode": "E2 7AA",
				"TownName": "London",
				"Country": "UK"
		}
	}
}`, value)
}
