package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/net"
	"github.com/zalando/skipper/proxy/proxytest"
)

const (
	kid                    = "mykid"
	validClaim3            = "sub"
	invalidSupportedClaim3 = "email"
)

var (
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

func createToken() string {
	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Unix() + 1000,
		Issuer:    "test",
		Subject:   "aaa",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	s, err := token.SignedString(privateKey)

	fmt.Printf("Token: %v %v", s, err)

	return s
}

func TestToken(t *testing.T) {
	s := createToken()

	publicKeyString := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())

	parsedToken, err := jwt.Parse(s, func(token *jwt.Token) (interface{}, error) {
		return parsePublicKey(publicKeyString), nil
	})

	if err != nil {
		t.Errorf("Failed to json decode: %v", err)
		return
	}

	err = parsedToken.Claims.Valid()

	if err != nil {
		t.Errorf("Failed token: %v", err)
		return
	}

}

func TestJWTValidation(t *testing.T) {
	cli := net.NewClient(net.Options{
		IdleConnTimeout: 2 * time.Second,
	})
	defer cli.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(489)
			return
		}

		allKeys := map[string][]interface{}{}
		allKeys["keys"] = append(allKeys["keys"], map[string]interface{}{"kid": kid, "n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()), "e": "AQAB"})
		if r.URL.Path != testAuthPath {
			w.WriteHeader(488)
			return
		}

		e := json.NewEncoder(w)
		err2 := e.Encode(allKeys)
		if err2 != nil && err2 != io.EOF {
			t.Errorf("Failed to json encode: %v", err2)
		}
	}))
	defer authServer.Close()

	testOidcConfig := getTestOidcConfig()
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != TokenIntrospectionConfigPath {
			w.WriteHeader(486)
			return
		}
		e := json.NewEncoder(w)
		err := e.Encode(testOidcConfig)
		if err != nil {
			t.Fatalf("Could not encode testOidcConfig: %v", err)
		}
	}))
	defer issuerServer.Close()

	// patch openIDConfig to the current testservers
	testOidcConfig.Issuer = "http://" + issuerServer.Listener.Addr().String()
	testOidcConfig.IntrospectionEndpoint = "http://" + authServer.Listener.Addr().String() + testAuthPath
	testOidcConfig.JwksURI = "http://" + authServer.Listener.Addr().String() + testAuthPath

	for _, ti := range []struct {
		msg         string
		authType    string
		authBaseURL string
		args        []interface{}
		hasAuth     bool
		auth        string
		expected    int
	}{{

		msg:      "jwtValidationAnyClaims: uninitialized filter, no authorization header, scope check",
		expected: invalidFilterExpected,
	}, {
		msg:         "jwtValidationAnyClaims: invalid token",
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim3},
		hasAuth:     true,
		auth:        "invalid-token",
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "jwtValidationAnyClaims: unsupported claim",
		authBaseURL: testAuthPath,
		args:        []interface{}{"unsupported-claim"},
		hasAuth:     true,
		auth:        createToken(),
		expected:    invalidFilterExpected,
	}, {
		msg:         "jwtValidationAnyClaims: valid claim",
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim3},
		hasAuth:     true,
		auth:        createToken(),
		expected:    http.StatusOK,
	}, {
		msg:         "jwtValidationAnyClaims: invalid claim",
		authBaseURL: testAuthPath,
		args:        []interface{}{invalidSupportedClaim3},
		hasAuth:     true,
		auth:        createToken(),
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "jwtValidationAnyClaims: valid token, one valid claim, one invalid supported claim",
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim3 + " " + invalidSupportedClaim3},
		hasAuth:     true,
		auth:        createToken(),
		expected:    http.StatusOK,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			if ti.msg == "" {
				t.Fatalf("unknown ti: %+v", ti)
			}

			var spec = NewJwtValidation(testAuthTimeout)

			args := []interface{}{testOidcConfig.Issuer}
			args = append(args, ti.args...)
			f, err := spec.CreateFilter(args)
			if err != nil {
				if ti.expected == invalidFilterExpected {
					return
				}
				t.Errorf("error in creating filter for %s: %v", ti.msg, err)
				return
			}

			f2 := f.(*jwtValidationFilter)
			defer f2.Close()

			fr := make(filters.Registry)
			fr.Register(spec)
			r := &eskip.Route{Filters: []*eskip.Filter{{Name: spec.Name(), Args: args}}, Backend: backend.URL}

			proxy := proxytest.New(fr, r)
			defer proxy.Close()

			reqURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Errorf("Failed to parse url %s: %v", proxy.URL, err)
				return
			}

			req, err := http.NewRequest("GET", reqURL.String(), nil)
			if err != nil {
				t.Errorf("failed to create request %v", err)
				return
			}

			if ti.hasAuth {
				req.Header.Set(authHeaderName, authHeaderPrefix+ti.auth)
			}

			rsp, err := cli.Do(req)
			if err != nil {
				t.Errorf("failed to get response: %v", err)
				return
			}
			defer rsp.Body.Close()

			if rsp.StatusCode != ti.expected {
				t.Errorf("unexpected status code: %v != %v", rsp.StatusCode, ti.expected)
				return
			}
		})
	}
}
