package domain

import "errors"

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrSessionExpired      = errors.New("session has expired")
	ErrInvalidAccessToken  = errors.New("invalid access token")
)
