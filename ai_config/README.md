# AI Config Files

This folder groups the DeepSeek AI integration notes in one place without
moving the runtime files that must stay at the project root.

Runtime files kept in place:

- `/.env`
- `/.env.example`
- `/env_loader.py`
- `/app.py`
- `/ai_service.py`
- `/test/test_env_loader.py`
- `/.gitignore`

What each file does:

- `/.env`: stores your real local API key and model settings
- `/.env.example`: reusable template for future environments
- `/env_loader.py`: loads `.env` and `.env.local` automatically
- `/app.py`: loads environment settings when the backend starts
- `/ai_service.py`: reads `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL`, `AI_TIMEOUT`
- `/ai_service.py`: ignores broken system proxy by default unless `AI_USE_ENV_PROXY=true`
- `/test/test_env_loader.py`: verifies the env loader behavior
- `/.gitignore`: prevents `.env` from being committed

Current DeepSeek settings:

- provider: DeepSeek
- base url: `https://api.deepseek.com/v1`
- model: `deepseek-chat`
- use env proxy: `false`

How to take effect:

1. Restart the backend service.
2. Open one asset detail page.
3. Click the AI analysis action to generate a result.

Notes:

- The real secret is stored only in `/.env`.
- Do not move the runtime files into this folder, or imports and auto-loading
  will break.
