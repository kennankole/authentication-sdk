package jwttoken

func NewJWTTokenClient(config JWTConfig) *JWTConfig {
	return &JWTConfig{
		SecreteKey: config.SecreteKey,
	}
}
