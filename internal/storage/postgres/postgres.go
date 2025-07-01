package postgres

import (
	"context"
	"errors"
	"fmt"
	"test2auth/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func New(storageURL string) (*Storage, error) {
	const op = "storage.postgres.New"

	pool, err := pgxpool.New(context.Background(), storageURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{pool: pool}, nil
}

func (s *Storage) SaveSession(ctx context.Context, session domain.Session) error {
	const op = "storage.postgres.SaveSession"

	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (user_id, refresh_token, user_agent, ip, expires_at) 
		 VALUES ($1, $2, $3, $4, $5)`,
		session.UserID, session.RefreshTokenHash, session.UserAgent, session.IP, session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetSession(ctx context.Context, userID uuid.UUID) (domain.Session, error) {
	const op = "storage.postgres.GetSession"

	var session domain.Session
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, refresh_token, user_agent, ip, expires_at, created_at 
		 FROM sessions WHERE user_id = $1`,
		userID,
	).Scan(
		&session.UserID,
		&session.RefreshTokenHash,
		&session.UserAgent,
		&session.IP,
		&session.ExpiresAt,
		&session.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, fmt.Errorf("%s: %w", op, domain.ErrSessionNotFound)
		}
		return domain.Session{}, fmt.Errorf("%s: %w", op, err)
	}

	return session, nil
}

func (s *Storage) DeleteSession(ctx context.Context, userID uuid.UUID) error {
	const op = "storage.postgres.DeleteSession"

	_, err := s.pool.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
