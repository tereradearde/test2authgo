# Сервис Аутентификации

Простой сервис аутентификации на Go.

### Установка и запуск

1.  Клонируйте репозиторий.
    ```bash
    git clone https://github.com/tereradearde/test2authgo.git
    cd test2auth
    ```
2.  Создайте файл `.env` из примера.
    ```bash
    git clone https://github.com/your-username/test2auth.git
    cd test2auth
    ```
3.  Запустите всё с помощью Docker.
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
