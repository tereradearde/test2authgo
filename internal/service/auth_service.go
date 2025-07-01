package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"test2auth/domain"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:generate go run github.com/vektra/mockery/v2@v2.42.1 --name=AuthService
type AuthService interface {
	CreateTokens(ctx context.Context, userID uuid.UUID, userAgent, ip string) (accessToken, refreshToken string, err error)
	RefreshTokens(ctx context.Context, accessToken, refreshToken, userAgent, ip string) (newAccessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, userID uuid.UUID) error
}

type Storage interface {
	SaveSession(ctx context.Context, session domain.Session) error
	GetSession(ctx context.Context, userID uuid.UUID) (domain.Session, error)
	DeleteSession(ctx context.Context, userID uuid.UUID) error
}

type authService struct {
	storage    Storage
	log        *slog.Logger
	jwtSecret  string
	webhookURL string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewAuthService(storage Storage, log *slog.Logger, jwtSecret, webhookURL string, accessTTL, refreshTTL time.Duration) AuthService {
	return &authService{
		storage:    storage,
		log:        log,
		jwtSecret:  jwtSecret,
		webhookURL: webhookURL,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (s *authService) CreateTokens(ctx context.Context, userID uuid.UUID, userAgent, ip string) (string, string, error) {
	const op = "service.auth.CreateTokens"

	accessToken, err := s.createAccessToken(userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err := s.createRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	session := domain.Session{
		UserID:           userID,
		RefreshTokenHash: string(refreshTokenHash),
		UserAgent:        userAgent,
		IP:               ip,
		ExpiresAt:        time.Now().Add(s.refreshTTL),
	}

	if err := s.storage.SaveSession(ctx, session); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, base64.StdEncoding.EncodeToString([]byte(refreshToken)), nil
}

func (s *authService) RefreshTokens(ctx context.Context, accessToken, refreshToken, userAgent, ip string) (string, string, error) {
	const op = "service.auth.RefreshTokens"

	// Декодирование refresh token
	decodedRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, domain.ErrInvalidRefreshToken)
	}

	// Парсинг access token для получения user_id
	claims, err := s.parseAccessToken(accessToken)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return "", "", fmt.Errorf("%s: invalid user id in token: %w", op, err)
	}

	// Получение сессии из хранилища
	session, err := s.storage.GetSession(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Проверка на несоответствие User-Agent
	if session.UserAgent != userAgent {
		s.log.Warn("user-agent mismatch on token refresh", slog.String("user_id", userID.String()))
		s.storage.DeleteSession(ctx, userID) // Deauthorize user
		return "", "", fmt.Errorf("%s: user-agent mismatch", op)
	}

	// Проверка на изменение IP
	if session.IP != ip {
		s.log.Warn("ip address mismatch on token refresh", slog.String("user_id", userID.String()), slog.String("new_ip", ip))
		s.sendIPMismatchWebhook(userID.String(), session.IP, ip)
	}

	// Проверка на истечение срока действия сессии
	if time.Now().After(session.ExpiresAt) {
		s.storage.DeleteSession(ctx, userID)
		return "", "", fmt.Errorf("%s: %w", op, domain.ErrSessionExpired)
	}

	// Сравнение refresh токенов
	if err := bcrypt.CompareHashAndPassword([]byte(session.RefreshTokenHash), decodedRefreshToken); err != nil {
		s.storage.DeleteSession(ctx, userID)
		return "", "", fmt.Errorf("%s: %w", op, domain.ErrInvalidRefreshToken)
	}

	// Удаление старой сессии для предотвращения повторного использования
	if err := s.storage.DeleteSession(ctx, userID); err != nil {
		return "", "", fmt.Errorf("%s: failed to delete old session: %w", op, err)
	}

	// Создание новых токенов
	return s.CreateTokens(ctx, userID, userAgent, ip)
}

func (s *authService) parseAccessToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		// Обработка ошибки истечения срока действия токена для возможности обновления
		if verr, ok := err.(*jwt.ValidationError); ok && verr.Errors == jwt.ValidationErrorExpired {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				return claims, nil
			}
		}
		return nil, domain.ErrInvalidAccessToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, domain.ErrInvalidAccessToken
}

func (s *authService) createAccessToken(userID uuid.UUID) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(s.accessTTL).Unix(),
	})
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authService) createRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func (s *authService) sendIPMismatchWebhook(userID, oldIP, newIP string) {
	const op = "service.auth.sendIPMismatchWebhook"

	payload := map[string]string{
		"user_id": userID,
		"old_ip":  oldIP,
		"new_ip":  newIP,
		"message": "A token refresh attempt was made from a new IP address.",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("failed to marshal webhook payload", slog.String("op", op), "error", err)
		return
	}

	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		s.log.Error("failed to send webhook", slog.String("op", op), "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.log.Error("webhook returned non-200 status", slog.String("op", op), "status", resp.Status)
	}
}

func (s *authService) Logout(ctx context.Context, userID uuid.UUID) error {
	const op = "service.auth.Logout"

	if err := s.storage.DeleteSession(ctx, userID); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
