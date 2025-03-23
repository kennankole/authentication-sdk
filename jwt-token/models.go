package jwttoken

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	PhoneNumber string
	Verified    bool
	jwt.RegisteredClaims
}

type JWTConfig struct {
	SecreteKey []byte
}
