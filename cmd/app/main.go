package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"test2auth/internal/config"
	authhttp "test2auth/internal/handler/http"
	"test2auth/internal/service"
	"test2auth/internal/storage/postgres"

	_ "test2auth/docs" // swag init

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Auth Service API
// @version 1.0
// @description This is a simple authentication service.
// @host localhost:8080
// @BasePath /
func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting application", slog.String("env", cfg.Env))

	storage, err := postgres.New(cfg.StorageURL)
	if err != nil {
		log.Error("failed to init storage", "error", err)
		os.Exit(1)
	}

	runMigrations(cfg.StorageURL, log)

	authService := service.NewAuthService(
		storage,
		log,
		cfg.JWT.Secret,
		cfg.WebhookURL,
		cfg.JWT.AccessTTL,
		cfg.JWT.RefreshTTL,
	)
	authHandler := authhttp.NewAuthHandler(authService, cfg.JWT.Secret)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.Post("/auth/tokens", authHandler.CreateTokens)
	router.Post("/auth/tokens/refresh", authHandler.RefreshTokens)

	router.Group(func(r chi.Router) {
		r.Use(authHandler.AuthMiddleware)
		r.Get("/me", authHandler.GetMyGUID)
		r.Post("/logout", authHandler.Logout)
	})

	router.Get("/swagger/*", httpSwagger.WrapHandler)

	address := cfg.HTTPServer.Host + ":" + cfg.HTTPServer.Port
	log.Info("starting server", slog.String("address", address))

	srv := &http.Server{
		Addr:         address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	<-stop

	log.Info("shutting down server gracefully")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("server shutdown failed", "error", err)
		os.Exit(1)
	}

	log.Info("server stopped")
}

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}

func runMigrations(storageURL string, log *slog.Logger) {
	m, err := migrate.New(
		"file://migrations",
		storageURL,
	)
	if err != nil {
		log.Error("failed to create migrate instance", "error", err)
		os.Exit(1)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Error("failed to apply migrations", "error", err)
		os.Exit(1)
	}

	log.Info("migrations applied successfully")
}
