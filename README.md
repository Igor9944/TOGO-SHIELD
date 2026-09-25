# TOGO-SHIELD

A comprehensive cybersecurity threat analysis platform focused on detecting phishing, analyzing, and preventing digital threats in the African context, with special emphasis on Togo.

## Features

- Telegram Bot Interface (@TOGOShieldBot) for real-time threat analysis
- Web Dashboard for administration and monitoring
- Risk Engine for scoring threats (0-100 scale)
- URL Analyzer for detecting malicious links
- Image analysis capabilities (OCR ready)
- Campaign management for threat tracking
- PostgreSQL database for persistent storage
- Docker containerization for easy deployment

## Architecture

The platform follows a modular architecture:

```
TELEGRAM
    ↓
Telegram Bot API
    ↓
Webhook HTTPS
    ↓
FASTAPI BACKEND
    ↓
┌─────────────┼──────────────────┐
│             │                  │
▼             ▼                  ▼
Telegram Service Risk Engine   AI Service
    │             │                  │
    └─────────────┼──────────────────┘
                  ▼
            PostgreSQL
                  ▼
            Dashboard React
```

## Installation

```bash
docker compose up --build
```

The API is available at `http://localhost:8000` and the web dashboard at
`http://localhost:5173` during development. The default database URL targets
the PostgreSQL service from Compose; local development falls back to SQLite
when `DATABASE_URL` is not set.

## Environment Variables

Configure the local `.env` file with the required values:

- DATABASE_URL: PostgreSQL connection string
- JWT_SECRET_KEY: Secret key for JWT tokens
- TELEGRAM_BOT_TOKEN: Token from @BotFather
- TELEGRAM_WEBHOOK_URL: Your webhook URL (for production)
- TELEGRAM_WEBHOOK_SECRET: Secret for webhook validation
- AI_PROVIDER: AI provider (mock, localai, openai, etc.)

## Usage

1. Start the services: `docker compose up --build`
2. Configure a bot with `@BotFather`, then set `TELEGRAM_BOT_TOKEN` in `.env`.
3. Set `TELEGRAM_ENABLED=true` and configure the webhook secret in production.
4. Use `POST /api/telegram/webhook` for Telegram updates or
     `POST /api/telegram/simulate` for a local demonstration.

### API smoke test

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/scans \
    -H 'content-type: application/json' \
    -d '{"content":"URGENT: envoyez votre OTP sur https://example.com"}'
```

The current MVP stores scans in PostgreSQL (or SQLite locally), applies a
transparent rules and URL score, and formats Telegram replies without ever
visiting submitted URLs. OCR, JWT administration, Alembic migrations and
campaign management remain extension points for the next iteration.

## Development

For local development:
1. Backend: `uvicorn app.main:app --reload`
2. Frontend: `npm run dev` (in frontend directory)

## Testing

Run tests with: `pytest` (backend) and appropriate frontend test commands.

## Provider keys

`VIRUSTOTAL_API_KEY` and `URLHAUS_API_KEY` are optional backend-only keys.
They are used with short timeouts for reputation lookups; submitted URLs are
never opened by the server. Keep real keys in `.env`; `.env.example` is safe
to commit.

## License

MIT License