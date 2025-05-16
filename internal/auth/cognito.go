package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
	Use string `json:"use"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type CognitoConfig struct {
	Region     string
	UserPoolID string
	ClientID   string
	TokenUse   string
	jwks       *JWKS
	jwksLock   sync.RWMutex
	httpClient *resty.Client
}

func NewCognitoConfig() *CognitoConfig {
	return &CognitoConfig{
		Region:     os.Getenv("AWS_COGNITO_REGION"),
		UserPoolID: os.Getenv("AWS_COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("AWS_COGNITO_CLIENT_ID"),
		TokenUse:   "access",
		httpClient: resty.New().SetTimeout(10 * time.Second),
	}
}

func (c *CognitoConfig) GetJWKSURL() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", c.Region, c.UserPoolID)
}

// JWKS를 가져오는 함수
func (c *CognitoConfig) fetchJWKS() error {
	resp, err := c.httpClient.R().Get(c.GetJWKSURL())
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(resp.Body(), &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %v", err)
	}

	c.jwksLock.Lock()
	c.jwks = &jwks
	c.jwksLock.Unlock()

	return nil
}

// Base64URL 디코딩 함수
func decodeBase64URL(str string) ([]byte, error) {
	padded := str
	switch len(str) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}
	return base64.URLEncoding.DecodeString(padded)
}

// JWK를 RSA 공개키로 변환하는 함수
func (jwk *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	// 지수(e) 디코딩
	decodedE, err := decodeBase64URL(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	// 4바이트 지수로 변환
	var e uint64
	if len(decodedE) < 4 {
		e = uint64(binary.BigEndian.Uint32(append(make([]byte, 4-len(decodedE)), decodedE...)))
	} else {
		e = uint64(binary.BigEndian.Uint32(decodedE[:4]))
	}

	// 모듈러스(n) 디코딩
	decodedN, err := decodeBase64URL(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}

	n := new(big.Int).SetBytes(decodedN)

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}

func (c *CognitoConfig) getPublicKey(kid string) (*rsa.PublicKey, error) {
	c.jwksLock.RLock()
	if c.jwks == nil {
		c.jwksLock.RUnlock()
		if err := c.fetchJWKS(); err != nil {
			return nil, err
		}
		c.jwksLock.RLock()
	}
	defer c.jwksLock.RUnlock()

	for _, key := range c.jwks.Keys {
		if key.Kid == kid {
			return key.toRSAPublicKey()
		}
	}

	// kid를 찾지 못한 경우 JWKS를 다시 가져와서 재시도
	c.jwksLock.RUnlock()
	if err := c.fetchJWKS(); err != nil {
		return nil, err
	}
	c.jwksLock.RLock()

	for _, key := range c.jwks.Keys {
		if key.Kid == kid {
			return key.toRSAPublicKey()
		}
	}

	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}

// TokenClaims는 검증된 토큰의 클레임을 담는 구조체입니다.
type TokenClaims struct {
	Sub string
}

func (c *CognitoConfig) ValidateToken(tokenString string) (*TokenClaims, error) {
	// JWT 토큰의 헤더를 파싱하여 키 ID(kid) 추출
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token header: %v", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse token header: %v", err)
	}

	// 토큰 검증
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 알고리즘 검증
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid token claims")
		}

		// 토큰 용도 검증
		tokenUse, ok := claims["token_use"].(string)
		if !ok || tokenUse != c.TokenUse {
			return nil, fmt.Errorf("invalid token use")
		}

		// Client ID 검증
		aud, ok := claims["client_id"].(string)
		if !ok || aud != c.ClientID {
			return nil, fmt.Errorf("invalid client id")
		}

		// Issuer 검증
		iss, ok := claims["iss"].(string)
		expectedIss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", c.Region, c.UserPoolID)
		if !ok || iss != expectedIss {
			return nil, fmt.Errorf("invalid issuer")
		}

		// 만료 시간 검증
		exp, ok := claims["exp"].(float64)
		if !ok || float64(time.Now().Unix()) > exp {
			return nil, fmt.Errorf("token expired")
		}

		// JWKS에서 공개키 가져오기
		return c.getPublicKey(header.Kid)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// sub 클레임 추출
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("missing sub claim")
	}

	return &TokenClaims{
		Sub: sub,
	}, nil
}
