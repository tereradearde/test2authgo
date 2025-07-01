package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"test2auth/domain"

	"github.com/google/uuid"
)

type AuthService interface {
	CreateTokens(ctx context.Context, userID uuid.UUID, userAgent, ip string) (accessToken, refreshToken string, err error)
	RefreshTokens(ctx context.Context, accessToken, refreshToken, userAgent, ip string) (newAccessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, userID uuid.UUID) error
}

type AuthHandler struct {
	authService AuthService
	jwtSecret   string
}

func NewAuthHandler(authService AuthService, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtSecret:   jwtSecret,
	}
}

type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type errorResponse struct {
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResponse{Message: message})
}

// CreateTokens godoc
// @Summary      Create a new pair of tokens
// @Description  Create access and refresh tokens for a user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user_id query string true "User ID (GUID)"
// @Success      200 {object} tokensResponse
// @Failure      400 {object} errorResponse
// @Failure      500 {object} errorResponse
// @Router       /auth/tokens [post]
func (h *AuthHandler) CreateTokens(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	userAgent := r.UserAgent()
	ip := r.RemoteAddr

	accessToken, refreshToken, err := h.authService.CreateTokens(r.Context(), userID, userAgent, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create tokens")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

type refreshRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokens godoc
// @Summary      Refresh a pair of tokens
// @Description  Refresh access and refresh tokens using a valid refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input body refreshRequest true "Access and Refresh Tokens"
// @Success      200 {object} tokensResponse
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      500 {object} errorResponse
// @Router       /auth/tokens/refresh [post]
func (h *AuthHandler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userAgent := r.UserAgent()
	ip := r.RemoteAddr

	newAccessToken, newRefreshToken, err := h.authService.RefreshTokens(r.Context(), req.AccessToken, req.RefreshToken, userAgent, ip)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidRefreshToken) || errors.Is(err, domain.ErrSessionExpired) || errors.Is(err, domain.ErrSessionNotFound) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokensResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
}

type guidResponse struct {
	UserID string `json:"user_id"`
}

// GetMyGUID godoc
// @Summary      Get current user's GUID
// @Description  Get GUID of the user associated with the provided access token
// @Tags         auth
// @Produce      json
// @Security     ApiKeyAuth
// @Success      200 {object} guidResponse
// @Failure      401 {object} errorResponse
// @Router       /me [get]
func (h *AuthHandler) GetMyGUID(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(UserIDContextKey).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "user_id not found in context")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(guidResponse{UserID: userID})
}

// Logout godoc
// @Summary      Logout user
// @Description  Deauthorize the current user by deleting their session
// @Tags         auth
// @Security     ApiKeyAuth
// @Success      200
// @Failure      401 {object} errorResponse
// @Failure      500 {object} errorResponse
// @Router       /logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := r.Context().Value(UserIDContextKey).(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "user_id not found in context")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid user_id in context")
		return
	}

	if err := h.authService.Logout(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to logout")
		return
	}

	w.WriteHeader(http.StatusOK)
}
