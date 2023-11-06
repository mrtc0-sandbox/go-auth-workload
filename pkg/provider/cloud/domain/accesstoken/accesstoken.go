package accesstoken

import (
	"crypto/rand"
	"fmt"
)

func GenerateAccessToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("access_token_%x", b)
}
