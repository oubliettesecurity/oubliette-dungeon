const BASE = "/api/dungeon";

export interface ScenarioSummary {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  description: string;
  multi_turn: boolean;
  prompt: string;
  owasp_mapping: string[];
  mitre_mapping: string[];
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
  bypass_indicators_found: string[];
  safe_indicators_found: string[];
  notes: string;
}

export interface SessionMeta {
  session_id: string;
  started_at: string;
  total_tests: number;
  updated_at?: string;
}

export interface SessionStats {
  session_id: string;
  total_tests: number;
  started_at: string;
  updated_at: string;
  by_result: Record<string, number>;
  by_category: Record<string, number>;
  by_difficulty: Record<string, number>;
  avg_execution_time_ms: number;
  avg_confidence: number;
  detection_rate: number;
  bypass_rate: number;
  high_confidence_tests: number;
}

export interface ScenarioStats {
  total: number;
  multi_turn_count: number;
  by_category: Record<string, number>;
  by_difficulty: Record<string, number>;
}

export interface ScheduleJob {
  job_id: string;
  name: string;
  cron: string;
  target_url: string;
  enabled: boolean;
  last_run: string | null;
  next_run: string | null;
  categories: string[];
  difficulty: string[];
  notification: Record<string, string>;
}

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const getScenarios = () =>
  api<{ count: number; scenarios: ScenarioSummary[] }>("/scenarios").then(
    (r) => r.scenarios
  );

export const getScenarioStats = () => api<ScenarioStats>("/scenarios/stats");

export const startSession = (target?: string) =>
  api<{ session_id: string }>("/start", {
    method: "POST",
    body: JSON.stringify({ target_url: target }),
  });

export const getStatus = () => api<Record<string, unknown>>("/status");

export const getSessions = () =>
  api<{ count: number; sessions: SessionMeta[] }>("/sessions").then(
    (r) => r.sessions
  );

export const getLatestSession = () =>
  api<{ count: number; sessions: SessionMeta[] }>("/sessions").then((r) => {
    if (r.sessions.length === 0) return null;
    const latest = r.sessions[0];
    return getSessionStats(latest.session_id);
  });

export const getSessionResults = (id: string) =>
  api<{ session_id: string; results: SessionResult[] }>(
    `/results/${id}`
  ).then((r) => r.results);

export const getSessionStats = (id: string) =>
  api<SessionStats>(`/results/${id}/summary`);

export const getScheduleJobs = () =>
  api<{ jobs: ScheduleJob[] }>("/schedule").then((r) => r.jobs);

export const createScheduleJob = (job: Partial<ScheduleJob>) =>
  api<ScheduleJob>("/schedule", {
    method: "POST",
    body: JSON.stringify(job),
  });

export const downloadPdf = (id: string) =>
  fetch(`${BASE}/results/${id}/pdf`).then((r) => r.blob());
