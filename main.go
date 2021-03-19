package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	_ "github.com/lestrrat-go/jwx/jws"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var acMutex = &sync.Mutex{}
var GlobalAccessToken string

func hello(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "free text\n")
}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {
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
	consentReq.Header.Set("X-Fapi-Financial-Id", "001580000103UAvAAM")
	consentReq.Header.Set("Content-Type", "application/json")
	consentReq.Header.Set("X-Idempotency-Key", fmt.Sprintf("%d", n))
	consentReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ar.AccessToken))
	consentReq.Header.Set("X-Jws-Signature", signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	respB, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(respB))
}

type AccessResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func SignPayload(payload string) (string, error) {

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.PS256)
	headers.Set(jws.KeyIDKey, "7c992d92-41ae-4c26-a393-54aa9c9310c9")
	headers.Set(jws.CriticalKey, []string{"http://openbanking.org.uk/tan"})
	headers.Set("http://openbanking.org.uk/tan", "openbanking-demo.tymurkhr.repl.co")

	keyBytes, err := os.ReadFile("private.key")
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err

	}
	sign, err := jws.Sign([]byte(payload), jwa.PS256, key, jws.WithHeaders(headers))
	if err != nil {
		return "", err

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
	cert, err := tls.LoadX509KeyPair("transport.pem", "private.key")
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