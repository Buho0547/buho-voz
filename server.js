import express from "express";
import OpenAI from "openai";
import { OpenAIRealtimeWS } from "openai/realtime/ws";
import { BUSINESS_KNOWLEDGE } from "./knowledge.js";

const {
  OPENAI_API_KEY,
  OPENAI_PROJECT_ID,
  OPENAI_WEBHOOK_SECRET,
  PORT = "10000",
} = process.env;

for (const name of [
  "OPENAI_API_KEY",
  "OPENAI_PROJECT_ID",
  "OPENAI_WEBHOOK_SECRET",
]) {
  if (!process.env[name]) {
    console.error(`Falta la variable de entorno ${name}`);
    process.exit(1);
  }
}

const openai = new OpenAI({
  apiKey: OPENAI_API_KEY,
  project: OPENAI_PROJECT_ID,
  webhookSecret: OPENAI_WEBHOOK_SECRET,
});

const app = express();
const activeCalls = new Map();

const BUHO_INSTRUCTIONS = `
Eres Búho, el asistente telefónico de inteligencia artificial de El Búho de la Suerte.

Habla siempre en español de España.
Tu forma de hablar debe ser natural, clara, breve y profesional.
Haz una sola pregunta cada vez y deja hablar al cliente.
Si el cliente te interrumpe, deja de hablar y escucha.

IDENTIDAD Y PRESENTACIÓN

Al inicio de cada llamada debes identificarte una sola vez como
el asistente de inteligencia artificial de El Búho de la Suerte.

Después del saludo inicial, NO vuelvas a presentarte,
NO vuelvas a decir tu nombre y NO vuelvas a explicar que eres
una inteligencia artificial en cada respuesta.

Responde directamente a las preguntas del cliente.

Solo debes volver a explicar que eres un asistente de inteligencia
artificial si el cliente te pregunta expresamente quién eres,
si eres una persona o si está hablando con una inteligencia artificial.

Nunca afirmes que eres una persona.
Nunca afirmes que eres una persona.

REGLA PRINCIPAL:
Nunca inventes información. Si no conoces un dato o no puedes verificarlo, dilo claramente.

En esta primera versión de pruebas:
- Puedes explicar de forma general qué es El Búho de la Suerte.
- Puedes recoger verbalmente el motivo de una llamada.
- Todavía NO tienes acceso real a reservas, disponibilidad de números, pedidos ni pagos.
- Si preguntan por disponibilidad concreta de un número de lotería, explica que todavía no puedes comprobarla en tiempo real.
- Nunca confirmes una reserva, una compra, un premio ni una disponibilidad que no hayas verificado.
- No solicites datos bancarios, PIN, contraseñas ni datos completos de tarjetas.
- Si se trata de una operación relacionada con juego o participación en loterías, no la tramites para menores de 18 años.

Si no puedes resolver una consulta, indica que durante esta fase de pruebas la consulta deberá revisarla una persona de la administración.

Sé conciso. No hagas discursos largos.
${BUSINESS_KNOWLEDGE}
`.trim();

const WELCOME_MESSAGE =
  "Buenos días, has llamado a El Búho de la Suerte. " +
  "Soy Búho, el asistente de inteligencia artificial de la administración. " +
  "¿En qué puedo ayudarte?";

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    service: "buho-voz",
    message: "Servidor de Búho operativo",
  });
});

// OpenAI firma el cuerpo exacto del webhook, por eso aquí lo recibimos como texto
// y NO como JSON ya parseado.
app.post(
  "/openai/webhook",
  express.text({ type: "*/*", limit: "1mb" }),
  async (req, res) => {
    let event;

    try {
      event = await openai.webhooks.unwrap(req.body, req.headers);
    } catch (error) {
      console.error("Webhook rechazado: firma no válida.", error);
      return res.status(400).send("Invalid webhook signature");
    }

    if (event.type !== "realtime.call.incoming") {
      console.log("Webhook recibido:", event.type);
      return res.status(200).json({ ok: true });
    }

    const callId = event.data.call_id;
    console.log("Llamada SIP entrante:", callId);

    try {
      await openai.realtime.calls.accept(callId, {
  type: "realtime",
  model: "gpt-realtime-2.1-mini",

  audio: {
    output: {
      voice: "marin",
      speed: 0.96
    }
  },

  instructions: BUHO_INSTRUCTIONS,
  output_modalities: ["audio"],
  tracing: "auto",
});

      console.log("Llamada aceptada:", callId);

      // Conexión de control lateral ("sideband") a la llamada SIP ya aceptada.
      // Nos permite forzar el saludo inicial y, más adelante, ejecutar herramientas.
      const realtime = new OpenAIRealtimeWS({ callID: callId });
      activeCalls.set(callId, realtime);

      realtime.on("error", (error) => {
        console.error(`Realtime error en ${callId}:`, error);
      });

      realtime.socket.on("open", () => {
        console.log("Canal de control abierto:", callId);

        realtime.send({
          type: "response.create",
          response: {
            instructions: `Di exactamente este saludo, y nada más por ahora: "${WELCOME_MESSAGE}"`,
          },
        });
      });

      realtime.socket.on("close", () => {
        console.log("Canal de control cerrado:", callId);
        activeCalls.delete(callId);
      });

      return res.status(200).json({ ok: true });
    } catch (error) {
      console.error("No se pudo aceptar/configurar la llamada:", error);
      return res.status(500).json({ ok: false });
    }
  },
);

app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`Búho escuchando en el puerto ${PORT}`);
});
