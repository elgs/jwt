package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerate(t *testing.T) {
	secret := "secret"
	claim := map[string]interface{}{
		"a": "b",
		"c": 1.0,
	}
	token, err := Encode(claim, 3600, secret)
	assert.Nil(t, err)

	verified, err := Verify(token, secret)
	assert.Nil(t, err)
	assert.True(t, verified)

	decodedClaims, err := Decode(token)
	assert.Nil(t, err)
	assert.Equal(t, claim["a"], decodedClaims["a"])
	assert.Equal(t, claim["c"], decodedClaims["c"])
}
