package jwttoken

func NewJWTTokenClient(config JWTConfig) *JWTConfig {
	return &JWTConfig{
		SecretKey: config.SecretKey,
	}
}
