import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Model catalogue
// ---------------------------------------------------------------------------
const AI_MODELS = {
  gemini: [
    { id: "gemini-1.5-flash",  name: "Gemini 1.5 Flash",  inputCost: 0.075, outputCost: 0.30,  note: "Cheapest" },
    { id: "gemini-2.0-flash",  name: "Gemini 2.0 Flash",  inputCost: 0.10,  outputCost: 0.40,  note: "Latest" },
    { id: "gemini-1.5-pro",    name: "Gemini 1.5 Pro",    inputCost: 3.50,  outputCost: 10.50, note: "Most capable" },
  ],
  openai: [
    { id: "gpt-4o-mini", name: "GPT-4o Mini", inputCost: 0.15,  outputCost: 0.60,  note: "Cheapest" },
    { id: "gpt-4o",      name: "GPT-4o",      inputCost: 2.50,  outputCost: 10.00, note: "High capability" },
  ],
  anthropic: [
    { id: "claude-haiku-4-5-20251001", name: "Claude Haiku 4.5",  inputCost: 0.80,  outputCost: 4.00,  note: "Cheapest" },
    { id: "claude-sonnet-4-6",         name: "Claude Sonnet 4.6", inputCost: 3.00,  outputCost: 15.00, note: "Balanced" },
    { id: "claude-opus-4-7",           name: "Claude Opus 4.7",   inputCost: 15.00, outputCost: 75.00, note: "Most capable" },
  ],
} as const;

type Provider = keyof typeof AI_MODELS;

interface AiConfig {
  provider: Provider;
  model: string;
  apiKey: string;
}

interface AnalysisResult {
  name: string;
  status: "safe" | "system" | "suspicious" | "unknown";
  category: string;
  description: string;
  removable: boolean;
  recommendation: string;
}

// ---------------------------------------------------------------------------
// Config persistence
// ---------------------------------------------------------------------------
const CONFIG_PATH = path.join(__dirname, "ai-config.json");

function loadConfig(): AiConfig | null {
  // Env vars take priority over saved file
  if (process.env.ANTHROPIC_API_KEY) {
    return { provider: "anthropic", model: "claude-haiku-4-5-20251001", apiKey: process.env.ANTHROPIC_API_KEY };
  }
  if (process.env.OPENAI_API_KEY) {
    return { provider: "openai", model: "gpt-4o-mini", apiKey: process.env.OPENAI_API_KEY };
  }
  if (process.env.GEMINI_API_KEY) {
    return { provider: "gemini", model: "gemini-1.5-flash", apiKey: process.env.GEMINI_API_KEY };
  }
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8")) as AiConfig;
    }
  } catch {}
  return null;
}

function saveConfig(cfg: AiConfig) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), "utf-8");
}

let aiConfig: AiConfig | null = loadConfig();

// ---------------------------------------------------------------------------
// AI provider calls
// ---------------------------------------------------------------------------
const SYSTEM_PROMPT = `You are a Windows system security and cleanup expert. Analyze Windows process names and classify each one.
Respond ONLY with valid JSON in this exact shape, no markdown, no extra text:
{"results":[{"name":"<process>","status":"safe|system|suspicious|unknown","category":"<category>","description":"<one sentence about what this process is>","removable":true|false,"recommendation":"<concise action advice>"}]}
Categories: System, Browser, Gaming, Utility, Security, Development, Media, Network, User, Unknown.
removable: true if the process is a leftover from uninstalled software, an unnecessary startup item, bloatware, or can be safely terminated and deleted without affecting Windows or actively used apps. false if it is essential to Windows stability or an app the user likely needs.
recommendation: A short, direct action note. Examples: "Safe to remove — leftover from Adobe CC uninstall", "Keep — core Windows service", "Investigate — unusual origin, check Task Manager", "Optional — only needed if you use Spotify".`;

async function callGemini(processNames: string[], cfg: AiConfig) {
  const { GoogleGenAI, Type } = await import("@google/genai");
  const ai = new GoogleGenAI({ apiKey: cfg.apiKey });
  const response = await ai.models.generateContent({
    model: cfg.model,
    contents: `Analyze these Windows process names: ${processNames.join(", ")}`,
    config: {
      systemInstruction: SYSTEM_PROMPT,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          results: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                name:           { type: Type.STRING },
                status:         { type: Type.STRING, enum: ["safe", "system", "suspicious", "unknown"] },
                category:       { type: Type.STRING },
                description:    { type: Type.STRING },
                removable:      { type: Type.BOOLEAN },
                recommendation: { type: Type.STRING },
              },
              required: ["name", "status", "category", "description", "removable", "recommendation"],
            },
          },
        },
        required: ["results"],
      },
    },
  });
  const parsed = JSON.parse(response.text ?? "{}");
  const usage = response.usageMetadata;
  return {
    results: parsed.results as AnalysisResult[],
    inputTokens: usage?.promptTokenCount ?? 0,
    outputTokens: usage?.candidatesTokenCount ?? 0,
  };
}

async function callOpenAI(processNames: string[], cfg: AiConfig) {
  const { default: OpenAI } = await import("openai");
  const client = new OpenAI({ apiKey: cfg.apiKey });
  const completion = await client.chat.completions.create({
    model: cfg.model,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user",   content: `Analyze these Windows process names: ${processNames.join(", ")}` },
    ],
  });
  const text = completion.choices[0]?.message?.content ?? "{}";
  const parsed = JSON.parse(text);
  return {
    results: parsed.results as AnalysisResult[],
    inputTokens: completion.usage?.prompt_tokens ?? 0,
    outputTokens: completion.usage?.completion_tokens ?? 0,
  };
}

async function callAnthropic(processNames: string[], cfg: AiConfig) {
  const Anthropic = (await import("@anthropic-ai/sdk")).default;
  const client = new Anthropic({ apiKey: cfg.apiKey });
  const message = await client.messages.create({
    model: cfg.model,
    max_tokens: 4096,
    system: SYSTEM_PROMPT,
    messages: [
      { role: "user", content: `Analyze these Windows process names: ${processNames.join(", ")}` },
    ],
  });
  const text = message.content[0].type === "text" ? message.content[0].text : "{}";
  const parsed = JSON.parse(text);
  return {
    results: parsed.results as AnalysisResult[],
    inputTokens: message.usage.input_tokens,
    outputTokens: message.usage.output_tokens,
  };
}

async function analyzeWithProvider(processNames: string[], cfg: AiConfig) {
  switch (cfg.provider) {
    case "gemini":    return callGemini(processNames, cfg);
    case "openai":    return callOpenAI(processNames, cfg);
    case "anthropic": return callAnthropic(processNames, cfg);
    default: throw new Error(`Unknown provider: ${cfg.provider}`);
  }
}

function estimateCost(provider: Provider, modelId: string, inputTokens: number, outputTokens: number) {
  const models = AI_MODELS[provider] as readonly { id: string; inputCost: number; outputCost: number }[];
  const model = models.find(m => m.id === modelId);
  if (!model) return 0;
  return (inputTokens / 1_000_000) * model.inputCost + (outputTokens / 1_000_000) * model.outputCost;
}

// ---------------------------------------------------------------------------
// Express server
// ---------------------------------------------------------------------------
async function startServer() {
  const app = express();
  const PORT = 3013;

  app.use(express.json({ limit: "1mb" }));

  // In-memory store for the current system state
  let systemState = {
    connected: false,
    lastUpdate: null as string | null,
    os: "",
    cpuUsage: 0,
    memory: { total: 0, used: 0, percent: 0 },
    processes: [] as object[],
    history: [] as { time: string; cpu: number; ram: number }[],
  };

  // ---- System data endpoints ----

  app.get("/api/status", (_req, res) => {
    res.json(systemState);
  });

  app.get("/api/agent-source", (req, res) => {
    const protocol = req.headers["x-forwarded-proto"] || req.protocol;
    const host = req.headers.host;
    const origin = `${protocol}://${host}`;
    const script = `import psutil
import requests
import time

API_URL = "${origin}/api/report"

def gather_data():
    memory = psutil.virtual_memory()
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            info = proc.info
            processes.append({
                "pid": info['pid'],
                "name": info['name'],
                "cpu": info['cpu_percent'],
                "memory": info['memory_info'].rss / (1024 * 1024)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {
        "os": "Windows/Machine",
        "cpuUsage": psutil.cpu_percent(interval=1),
        "memory": {
            "total": memory.total / (1024 * 1024),
            "used": memory.used / (1024 * 1024),
            "percent": memory.percent
        },
        "processes": sorted(processes, key=lambda x: x['memory'], reverse=True)[:50]
    }

print(f"Connecting to PC Pulse at {API_URL}...")
while True:
    try:
        data = gather_data()
        requests.post(API_URL, json=data)
        time.sleep(2)
    except Exception as e:
        print(f"Sync error: {e}")
        time.sleep(5)`;
    res.setHeader("Content-Type", "text/plain");
    res.send(script);
  });

  app.post("/api/report", (req, res) => {
    const { os, cpuUsage, memory, processes } = req.body;
    systemState = {
      ...systemState,
      connected: true,
      lastUpdate: new Date().toISOString(),
      os,
      cpuUsage,
      memory,
      processes: processes || [],
    };
    const point = {
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      cpu: cpuUsage,
      ram: memory.percent,
    };
    systemState.history = [...systemState.history, point].slice(-30);
    res.json({ success: true });
  });

  app.post("/api/disconnect", (_req, res) => {
    systemState.connected = false;
    res.json({ success: true });
  });

  // ---- AI config endpoints ----

  app.get("/api/ai-config", (_req, res) => {
    if (!aiConfig) {
      res.json({ provider: null, model: null, models: AI_MODELS });
      return;
    }
    res.json({ provider: aiConfig.provider, model: aiConfig.model, models: AI_MODELS });
  });

  app.post("/api/ai-config", (req, res) => {
    const { provider, model, apiKey, useEnv } = req.body as {
      provider?: Provider;
      model?: string;
      apiKey?: string;
      useEnv?: boolean;
    };

    if (useEnv) {
      // Re-scan env vars
      const fromEnv = loadConfig();
      if (fromEnv) {
        aiConfig = fromEnv;
        res.json({ success: true, provider: aiConfig.provider, model: aiConfig.model });
      } else {
        res.status(400).json({ error: "no_env_keys", message: "No API keys found in environment variables." });
      }
      return;
    }

    if (!provider || !model || !apiKey) {
      res.status(400).json({ error: "missing_fields" });
      return;
    }
    if (!(provider in AI_MODELS)) {
      res.status(400).json({ error: "invalid_provider" });
      return;
    }
    aiConfig = { provider, model, apiKey };
    saveConfig(aiConfig);
    res.json({ success: true });
  });

  // ---- AI analysis endpoint ----

  app.post("/api/analyze", async (req, res) => {
    if (!aiConfig) {
      res.status(400).json({ error: "no_provider_configured" });
      return;
    }
    const { processes } = req.body as { processes: string[] };
    if (!Array.isArray(processes) || processes.length === 0) {
      res.status(400).json({ error: "no_processes" });
      return;
    }
    try {
      const { results, inputTokens, outputTokens } = await analyzeWithProvider(processes.slice(0, 50), aiConfig);
      const estimatedCostUsd = estimateCost(aiConfig.provider, aiConfig.model, inputTokens, outputTokens);
      res.json({
        results,
        usage: { inputTokens, outputTokens, estimatedCostUsd },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: "analysis_failed", message });
    }
  });

  // ---- Vite / static serving ----

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
    if (aiConfig) {
      console.log(`AI provider: ${aiConfig.provider} / ${aiConfig.model}`);
    } else {
      console.log("AI provider: not configured (use Settings panel to configure)");
    }
  });
}

startServer();
