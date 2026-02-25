# mail generator

Краткий сайт техподдержки с формой заявки и отправкой писем на почту.

## Возможности
- Главная страница с описанием и контактами
- Отдельная страница заявки
- CAPTCHA (простая арифметика)
- Отправка заявок через SMTP (SMTPS 465 или STARTTLS 587)
- Настройки через `.env`

## Запуск
1. Скопируйте `.env.example` в `.env` и заполните значения.
2. Запустите сервер:

```powershell
go run .\backend
```

Откройте http://localhost:8080

## Docker
```powershell
docker compose up --build
```

## Переменные окружения
- `SMTP_HOST` — хост SMTP (например `smtp.yandex.ru`)
- `SMTP_PORT` — порт (465 или 587)
- `SMTP_USER` — логин почты
- `SMTP_PASS` — пароль приложения
- `SMTP_FROM` — адрес отправителя
- `MAIL_TO` — адрес получателя
- `COMPANY_NAME` — название компании
- `SUPPORT_EMAIL` — почта техподдержки
- `SUPPORT_PHONE` — телефон техподдержки
