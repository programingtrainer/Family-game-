---
name: Socket.IO behind Replit proxy
description: Replit preview origins differ from the Flask server's local host and port.
---

Socket.IO CORS should allow only known Replit preview origins from the workspace domain variables, including the preview's external `:8080` port, plus local development origins. Do not use a wildcard to work around a rejected preview origin. Published domains may need to be explicitly added because the workspace variables identify development domains.

**Why:** The browser's proxied origin uses the public Replit hostname and port while Flask sees its internal host and port. Socket.IO's default same-origin validation rejected the polling `POST`, interrupting live game and notification events.

**How to apply:** When changing Socket.IO CORS or deployment domains, verify the exact browser `Origin` and allow that hostname narrowly; test both the Replit preview connection and rejection of an unrelated origin.
