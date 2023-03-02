package digestRequest

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/context"
)

type httpClientKey struct{}

// HTTPClientKey will be used for a key of context
var HTTPClientKey httpClientKey

// ContextWithClient returns context with a specified *http.Client
func ContextWithClient(parent context.Context, client *http.Client) context.Context {
	return context.WithValue(parent, HTTPClientKey, client)
}

func clientFromContext(ctx context.Context) *http.Client {

	if client, ok := ctx.Value(HTTPClientKey).(*http.Client); ok {
		return client
	}

	return http.DefaultClient
}

// DigestRequest is a client for digest authentication requests
type DigestRequest struct {
	context.Context
	client             *http.Client
	username, password string
	nonceCount         nonceCount
}

type nonceCount int

func (nc nonceCount) String() string {

	c := int(nc)
	return fmt.Sprintf("%08x", c)
}

const algorithm = "algorithm"
const nonce = "nonce"
const opaque = "opaque"
const qop = "qop"
const realm = "realm"

const wwwAuthenticate = "Www-Authenticate"
const authorization = "Authorization"

var wanted = []string{algorithm, nonce, opaque, qop, realm}

// New makes a DigestRequest instance
func New(ctx context.Context, username, password string) *DigestRequest {

	return &DigestRequest{
		Context:  ctx,
		client:   clientFromContext(ctx),
		username: username,
		password: password,
	}
}

// Do does requests as http.Do does
func (r *DigestRequest) Do(req *http.Request) (*http.Response, error) {

	parts, err := r.makeParts(req)
	if err != nil {
		return nil, err
	}

	if parts != nil {
		req.Header.Set(authorization, r.makeAuthorization(req, parts))
	}

	return r.client.Do(req)
}

func (r *DigestRequest) makeParts(req *http.Request) (map[string]string, error) {

	authReq, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(authReq)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		return nil, nil
	}

	if len(resp.Header[wwwAuthenticate]) == 0 {
		return nil, fmt.Errorf("headers do not have %s", wwwAuthenticate)
	}

	headers := strings.Split(resp.Header[wwwAuthenticate][0], ",")
	parts := make(map[string]string, len(wanted))

	for _, r := range headers {

		for _, w := range wanted {

			if strings.Contains(r, w) {

				kv := strings.Split(r, `=`)
				if len(kv) > 1 {
					parts[w] = strings.Trim(kv[1], `"`)
				}
			}
		}
	}

	aval, ok := parts[algorithm]
	if ok {

		fmt.Printf("algorithm = %s\n", parts[algorithm])
		if strings.HasSuffix(aval, "-sess") {
			return nil, fmt.Errorf("not support session variant: %s", aval)
		}
	} else {
		fmt.Printf("no algorithm(use default)\n")
		parts[algorithm] = "MD5"
	}

	_, ok = parts[nonce]
	if !ok {
		return nil, fmt.Errorf("no nonce")
	}

	_, ok = parts[realm]
	if !ok {
		return nil, fmt.Errorf("no realm")
	}

	qval := parts[qop]
	if qval != "auth" {
		return nil, fmt.Errorf("not support quality of protection: %s", qval)
	}

	return parts, nil
}

func (r *DigestRequest) getNonceCount() string {

	r.nonceCount++
	return r.nonceCount.String()
}

func (r *DigestRequest) makeAuthorization(req *http.Request, parts map[string]string) string {

	cnonce := Generate(16)
	nc := r.getNonceCount()
	var response string

	fmt.Printf("algorithm(authorization) = %s\n", parts[algorithm])
	switch strings.ToUpper(parts[algorithm]) {
	case "SHA-256":
		ha1 := getSHA256([]string{r.username, parts[realm], r.password})
		ha2 := getSHA256([]string{req.Method, req.URL.Path})
		response = getSHA256([]string{ha1, parts[nonce], nc, cnonce, parts[qop], ha2})
	case "SHA-512":
		ha1 := getSHA512([]string{r.username, parts[realm], r.password})
		ha2 := getSHA512([]string{req.Method, req.URL.Path})
		response = getSHA512([]string{ha1, parts[nonce], nc, cnonce, parts[qop], ha2})
	default:
		ha1 := getMD5([]string{r.username, parts[realm], r.password})
		ha2 := getMD5([]string{req.Method, req.URL.Path})
		response = getMD5([]string{ha1, parts[nonce], nc, cnonce, parts[qop], ha2})
	}

	oval, ok := parts[opaque]
	if !ok {
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, qop=%s, nc=%s, cnonce="%s", response="%s"`,
			r.username,
			parts[realm],
			parts[nonce],
			req.URL.Path,
			parts[algorithm],
			parts[qop],
			nc,
			cnonce,
			response,
		)
	}

	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, qop=%s, nc=%s, cnonce="%s", response="%s", opaque="%s"`,
		r.username,
		parts[realm],
		parts[nonce],
		req.URL.Path,
		parts[algorithm],
		parts[qop],
		nc,
		cnonce,
		response,
		oval,
	)
}

func getMD5(texts []string) string {

	h := md5.New()
	_, _ = io.WriteString(h, strings.Join(texts, ":"))
	return hex.EncodeToString(h.Sum(nil))
}

func getSHA256(texts []string) string {

	h := sha256.New()
	_, _ = io.WriteString(h, strings.Join(texts, ":"))
	return hex.EncodeToString(h.Sum(nil))
}

func getSHA512(texts []string) string {

	h := sha512.New()
	_, _ = io.WriteString(h, strings.Join(texts, ":"))
	return hex.EncodeToString(h.Sum(nil))
}
