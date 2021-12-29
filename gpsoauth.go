// Package gpsoauth provides OAuth methods for Google Play Services.
package gpsoauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpClient = http.DefaultClient

func WithHTTPClient(c *http.Client) {
	httpClient = c
}

const (
	authURL = "https://android.clients.google.com/auth"

	b64Key7_3_29 = "" +
		"AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" +
		"iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" +
		"RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" +
		"6rmf5AAAAAwEAAQ=="
)

var (
	androidKey      *rsa.PublicKey
	androidKeyBytes []byte
)

func init() {
	var err error
	androidKeyBytes, err = base64.StdEncoding.DecodeString(b64Key7_3_29)
	if err != nil {
		panic(err)
	}
	i := bytesToLong(androidKeyBytes[:4]).Int64()
	mod := bytesToLong(androidKeyBytes[4 : 4+i])
	j := bytesToLong(androidKeyBytes[i+4 : i+4+4]).Int64()
	exponent := bytesToLong(androidKeyBytes[i+8 : i+8+j]).Int64()
	androidKey = &rsa.PublicKey{
		N: mod,
		E: int(exponent),
	}
}

func bytesToLong(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func signature(email, password string) (string, error) {
	hash := sha1.Sum(androidKeyBytes)
	msg := append([]byte(email), 0)
	msg = append(msg, []byte(password)...)
	encryptedLogin, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, androidKey, msg, nil)
	if err != nil {
		return "", err
	}
	sig := append([]byte{0}, hash[:4]...)
	sig = append(sig, encryptedLogin...)
	return base64.URLEncoding.EncodeToString(sig), nil
}

// Login fetches a token and gets an OAuth string for an email address and
// password for the given services.
func Login(email, password, androidID, app, clientSignature string, service ...string) (accessToken *Token, err error) {
	refreshToken, err := GetToken(email, password, androidID)
	if err != nil {
		return nil, err
	}
	return AccessTokenFromRefreshToken(email, refreshToken, androidID, app, clientSignature, service...), nil
}

func defaultValues(email, androidID string) url.Values {
	return url.Values{
		"androidId":       []string{androidID},
		"Email":           []string{email},
		"device_country":  []string{"us"},
		"operatorCountry": []string{"us"},
		"lang":            []string{"en_US"},
		"sdk_version":     []string{"17"},
		"has_permission":  []string{"1"},
	}
}

// GetToken fetches a token for an email address and password.
func GetToken(email, password, androidID string) (token string, err error) {
	sig, err := signature(email, password)
	if err != nil {
		return "", err
	}
	data := defaultValues(email, androidID)
	data.Set("accountType", "HOSTED_OR_GOOGLE")
	data.Set("add_account", "1")
	data.Set("EncryptedPasswd", string(sig))
	data.Set("service", "ac2dm")
	data.Set("source", "android")

	resp, err := httpClient.PostForm(authURL, data)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gpsoauth: %s: %s", resp.Status, b)
	}
	for _, line := range strings.Split(string(b), "\n") {
		sp := strings.SplitN(line, "=", 2)
		if len(sp) != 2 {
			continue
		}
		if sp[0] == "Token" {
			return sp[1], nil
		}
	}
	return "", fmt.Errorf("gpsoauth: no Token found")
}

type accessToken struct {
	token  string
	expiry time.Time
}

func getAccessToken(email, token, androidID string, app string, clientSignature string, service ...string) (*accessToken, error) {
	data := defaultValues(email, androidID)
	data.Set("app", app)
	data.Set("check_email", "1")
	for _, s := range service {
		data.Add("service", s)
	}
	data.Set("client_sig", clientSignature)
	data.Set("caller", app)
	data.Set("Token", token)
	data.Set("callerSig", clientSignature)

	resp, err := httpClient.PostForm(authURL, data)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gpsoauth: %s: %s", resp.Status, b)
	}

	var t accessToken

	for _, line := range strings.Split(string(b), "\n") {
		sp := strings.SplitN(line, "=", 2)
		if len(sp) != 2 {
			continue
		}
		if sp[0] == "Auth" {
			t.token = sp[1]
		}
		if sp[0] == "Expiry" {
			unixtime, err := strconv.ParseInt(sp[1], 10, 64)
			if err != nil {
				return nil, err
			}
			// ensure we don't use token close to expiry
			unixtime -= 60
			t.expiry = time.Unix(unixtime, 0)
		}
	}
	if t.token == "" {
		return nil, fmt.Errorf("gpsoauth: no Auth found")
	}
	if t.expiry.IsZero() {
		return nil, fmt.Errorf("gpsoauth: no expiry time detected")
	}
	return &t, nil
}

// GetNode returns the MAC address of an interface on the machine is a
// 12-character string, or generates one if no MAC address exists. Designed
// for use as the androidID parameter.
func GetNode() string {
	var addr []byte
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if len(i.HardwareAddr) < 6 {
			continue
		}
		addr = i.HardwareAddr
		break
	}
	if addr == nil {
		addr = make([]byte, 6)
		// Ignore errors.
		_, _ = rand.Read(addr)
	}
	return hex.EncodeToString(addr[:6])
}

type Token struct {
	refreshToken string
	refresh      func() (*accessToken, error)

	mtx         sync.Mutex
	accessToken *accessToken
}

func AccessTokenFromRefreshToken(email, refreshToken, androidID string, app string, clientSignature string, service ...string) *Token {
	return &Token{
		refreshToken: refreshToken,
		refresh: func() (*accessToken, error) {
			return getAccessToken(email, refreshToken, androidID, app, clientSignature, service...)
		},
	}
}

func (t *Token) Token() (string, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.accessToken == nil || t.accessToken.expiry.Before(time.Now()) {
		accessToken, err := t.refresh()
		if err != nil {
			return "", err
		}
		t.accessToken = accessToken
	}
	return t.accessToken.token, nil
}
