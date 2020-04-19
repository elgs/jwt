package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Encode compiles and signs a JWT from a claim and an expiration time in seconds from current time.
func Encode(claim map[string]interface{}, exp int, secret string) (string, error) {
	ex := time.Now().Add(time.Second * time.Duration(exp))
	expiration := ex.Format("2006-01-02 15:04:05")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","exp":"` + expiration + `"}`))
	// Build json payload and base64 encode it
	pl2, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(pl2)
	// Build signature with the new secret and base64 encode it.
	signature := hmac256(header+"."+payload, secret)
	jwt := header + "." + payload + "." + signature
	return jwt, nil
}

func Verify(jwt string, secret string) (bool, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false, errors.New("Invalid JWT Structure")
	}
	ha := hmac256(parts[0]+"."+parts[1], secret)
	return ha == parts[2], nil
}

// Decode decodes a JWT and returns the payload as a map[string]interface{}.
func Decode(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])

	// JSON decode payload
	var pldat map[string]interface{}
	if err := json.Unmarshal(payload, &pldat); err != nil {
		return nil, err
	}
	// JSON decode header
	var headdat map[string]interface{}
	if err := json.Unmarshal(header, &headdat); err != nil {
		return nil, err
	}
	// Extract and parse expiration date from header
	exp := headdat["exp"]
	if exp != nil {
		layout := "2006-01-02 15:04:05"
		expParsed, err := time.ParseInLocation(layout, fmt.Sprint(exp), time.Now().Location())
		if err != nil {
			return nil, err
		}
		// Check how old the JWT is.  Return an error if it is expired
		if time.Now().After(expParsed) {
			return nil, errors.New("Expired JWT")
		}
	}
	return pldat, nil
}

func hmac256(message, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
