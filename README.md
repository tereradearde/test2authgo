# Сервис Аутентификации

Простой сервис аутентификации на Go.

### Как запустить

1.  Создайте файл `.env` из `.env.example` (или просто переименуйте его).
    ```bash
    cp .env.example .env
    ```
2.  Запустите с помощью Docker.
    ```bash
    docker-compose -f docker-compose.yml up -d
    ```

### API

Сервис будет доступен по адресу `http://localhost:8080`.

- `POST /auth/tokens` - Создание пары токенов для пользователя
- `POST /auth/tokens/refresh` - Обновление токенов
- `GET /me` - Получение GUID текущего пользователя (защищено)
- `POST /logout` - Выход из системы (защищено)

Полная документация по API доступна через Swagger по адресу `http://localhost:8080/swagger/index.html`. 