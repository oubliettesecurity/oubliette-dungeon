const BASE = "/api/dungeon";

export interface ScenarioSummary {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  description: string;
  is_multi_turn: boolean;
}

export interface SessionResult {
  scenario_id: string;
  scenario_name: string;
  category: string;
  difficulty: string;
  result: string;
  confidence: number;
  response: string;
  execution_time_ms: number;
  timestamp: string;
}

export interface SessionSummary {
  session_id: string;
  total: number;
  detected: number;
  bypassed: number;
  partial: number;
  detection_rate: number;
}

export interface ScheduleJob {
  id: string;
  name: string;
  cron: string;
  target_url: string;
  enabled: boolean;
  last_run: string | null;
  next_run: string | null;
}

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const getScenarios = () => api<ScenarioSummary[]>("/scenarios");
export const getScenarioStats = () =>
  api<Record<string, unknown>>("/scenarios/stats");
export const startSession = (target?: string) =>
  api<{ session_id: string }>("/start", {
    method: "POST",
    body: JSON.stringify({ target_url: target }),
  });
export const getStatus = () => api<Record<string, unknown>>("/status");
export const getSessions = () => api<string[]>("/sessions");
export const getLatestSession = () => api<SessionSummary>("/sessions/latest");
export const getSessionResults = (id: string) =>
  api<SessionResult[]>(`/results/${id}`);
export const getSessionSummary = (id: string) =>
  api<SessionSummary>(`/results/${id}/summary`);
export const getScheduleJobs = () => api<ScheduleJob[]>("/schedule");
export const createScheduleJob = (job: Partial<ScheduleJob>) =>
  api<ScheduleJob>("/schedule", {
    method: "POST",
    body: JSON.stringify(job),
  });
export const downloadPdf = (id: string) =>
  fetch(`${BASE}/results/${id}/pdf`).then((r) => r.blob());
