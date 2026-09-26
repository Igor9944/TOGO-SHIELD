# TOGO-SHIELD

Plateforme de cybersécurité centrée sur la détection de phishing et l'analyse de contenus suspects dans le contexte africain, avec une adaptation aux usages au Togo.

## Fonctionnalités

- Interface Web React/Vite pour analyser des messages, URLs et fichiers
- Bot Telegram (@TOGOShieldBot) avec analyse de texte, URLs, images et documents
- Moteur de risque transparent avec score de 0 à 100
- Analyse d'URLs sans ouvrir les liens soumis
- OCR des images avec Tesseract
- Extraction de texte depuis PDF, TXT et DOCX
- Threat Intelligence via URLhaus et VirusTotal lorsqu'une clé est configurée
- Persistance PostgreSQL des analyses, y compris les analyses de fichiers et Telegram
- Historique et endpoints de dashboard pour le suivi des scans

## Architecture de production

```
WEB REACT/VITE ──────────────┐
                             │
TELEGRAM BOT ── Webhook ─────┤
                             ▼
                       FASTAPI BACKEND
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Risk Engine     File Analysis   Threat Intel
              │          OCR/PDF/DOCX    URLhaus/VT
              └──────────────┼──────────────┘
                             ▼
                        PostgreSQL
```

Le backend de production est **FastAPI dans `backend/`**. Le fichier racine `server.ts` correspond à une ancienne implémentation et n'est pas utilisé par les projets Vercel de production.

## Déploiement Vercel

- Backend : projet Vercel `togo-shield`
- Frontend : projet Vercel `togo-shield-web`
- Backend public : `https://togo-shield.vercel.app`
- Frontend public : `https://togo-shield-web.vercel.app`

Le frontend consomme le backend via `VITE_API_URL`.

## Limites fichiers

La limite applicative est fixée à **4 MB** afin de rester compatible avec la limite de requête des fonctions Vercel utilisée par ce projet.

Formats pris en charge :

- JPG / JPEG
- PNG / WEBP
- PDF
- TXT
- DOCX

## Installation locale

```bash
docker compose up --build
```

Le backend est disponible sur `http://localhost:8000` et le frontend sur `http://localhost:5173`.

### Backend

```bash
cd backend
uvicorn app.main:app --reload
```

### Frontend

```bash
npm install
npm run dev
```

## Variables d'environnement backend

Les secrets réels ne doivent jamais être commités dans Git.

Variables principales :

- `DATABASE_URL`
- `JWT_SECRET_KEY`
- `TELEGRAM_ENABLED`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_WEBHOOK_URL`
- `TELEGRAM_WEBHOOK_SECRET`
- `VIRUSTOTAL_API_KEY`
- `URLHAUS_API_KEY`

## Test rapide

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"content":"URGENT : envoyez votre OTP sur https://example.com"}'
```

## Sécurité

- Les URLs soumises sont analysées sans navigation côté serveur.
- Les clés API restent côté backend.
- Le webhook Telegram vérifie le secret `X-Telegram-Bot-API-Secret-Token`.
- Les journaux HTTP du service Telegram ne doivent pas contenir les URLs incluant le token du bot.

## Licence

MIT
