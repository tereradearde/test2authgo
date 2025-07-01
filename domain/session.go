package domain

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	UserID           uuid.UUID
	RefreshTokenHash string
	UserAgent        string
	IP               string
	ExpiresAt        time.Time
	CreatedAt        time.Time
}
