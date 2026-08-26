# Búho Voz — servidor mínimo

Servidor Node.js para recibir el webhook de llamadas SIP de OpenAI Realtime,
aceptar la llamada y lanzar el saludo inicial del agente Búho.

## Archivos

- `server.js`: servidor y webhook.
- `package.json`: dependencias y comando de arranque.
- `.env.example`: nombres de variables de entorno. No contiene secretos.
- `.gitignore`: evita subir secretos y dependencias.

## Variables de entorno necesarias

- `OPENAI_API_KEY`
- `OPENAI_PROJECT_ID`
- `OPENAI_WEBHOOK_SECRET`
- `PORT` (Render suele configurarlo automáticamente; el código usa 10000 como valor por defecto)

## Render

- Tipo: Web Service
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/`

## Webhook de OpenAI

Cuando Render esté desplegado, configura en OpenAI un webhook con:

`https://TU-SERVICIO.onrender.com/openai/webhook`

y suscribe el evento de llamadas Realtime entrantes.

Después copia el secreto del webhook de OpenAI a la variable:

`OPENAI_WEBHOOK_SECRET`

## Seguridad

Nunca subas tu API key a GitHub.
Guárdala únicamente como variable de entorno/secret en Render.
