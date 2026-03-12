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

// --- Comparisons ---

export interface ComparisonMeta {
  comparison_id: string;
  timestamp: string;
  model_count: number;
  models: string[];
  status: string;
}

export interface ModelRanking {
  model_id: string;
  total_scenarios: number;
  detected: number;
  bypassed: number;
  partial: number;
  errors: number;
  detection_rate: number;
  bypass_rate: number;
  avg_confidence: number;
  avg_execution_time_ms: number;
  pass_at_1: number;
  pass_at_5: number;
  by_category: Record<string, Record<string, unknown>>;
  by_difficulty: Record<string, Record<string, unknown>>;
}

export interface ComparisonReport {
  comparison_id: string;
  status: string;
  timestamp: string;
  model_count: number;
  ranking: ModelRanking[];
  scenario_matrix: Record<string, unknown>[];
  category_comparison: Record<string, Record<string, unknown>>;
}

export const getComparisons = () =>
  api<{ count: number; comparisons: ComparisonMeta[] }>("/comparisons").then(
    (r) => r.comparisons
  );

export const getComparison = (id: string) =>
  api<ComparisonReport>(`/comparisons/${id}`);

export const runComparison = (
  models: string[],
  opts?: { target_url?: string; category?: string; timeout?: number }
) =>
  api<{ comparison_id: string; status: string; models: string[] }>(
    "/comparisons/run",
    {
      method: "POST",
      body: JSON.stringify({ models, ...opts }),
    }
  );

// --- OSEF Reports ---

export interface OSEFAggregate {
  total_scenarios: number;
  total_detected: number;
  total_bypassed: number;
  total_partial: number;
  total_errors: number;
  overall_detection_rate: number;
  overall_bypass_rate: number;
  avg_confidence: number;
  avg_execution_time_ms: number;
  pass_at_1: number;
  pass_at_5: number;
  pass_at_10: number;
  by_category: Record<string, unknown>[];
  by_difficulty: Record<string, Record<string, unknown>>;
  by_severity: Record<string, number>;
}

export interface OSEFReport {
  osef_version: string;
  tool: string;
  tool_version: string;
  model_id: string;
  timestamp: string;
  session_id: string;
  evaluation_context: Record<string, unknown>;
  aggregate: OSEFAggregate;
  results: Record<string, unknown>[];
  framework_coverage: Record<string, unknown>;
}

export interface OSEFValidation {
  valid: boolean;
  osef_version: string;
  errors: string[];
  fields_checked: number;
}

export const getOSEFReport = (sessionId: string) =>
  api<OSEFReport>(`/osef/${sessionId}`);

export const getLatestOSEF = () => api<OSEFReport>("/osef/latest");

export const validateOSEF = (doc: Record<string, unknown>) =>
  api<OSEFValidation>("/osef/validate", {
    method: "POST",
    body: JSON.stringify(doc),
  });

// --- Reviews (HITL) ---

export interface ReviewSummary {
  total: number;
  pending: number;
  reviewed: number;
  auto_accepted: number;
  by_result: Record<string, number>;
}

export interface PendingReviewItem {
  scenario_id: string;
  scenario_name: string;
  category: string;
  difficulty: string;
  automated_result: string;
  automated_confidence: number;
  response_snippet: string;
  review_reason: string;
  bypass_indicators_found: string[];
  safe_indicators_found: string[];
}

export interface ReviewSubmission {
  scenario_id: string;
  reviewer: string;
  override_result: "detected" | "bypass" | "partial";
  override_confidence?: number;
  justification: string;
  tags?: string[];
}

export interface FlagOptions {
  confidence_threshold?: number;
  flag_partial?: boolean;
  flag_categories?: string[] | null;
}

export const getReviewSummary = () =>
  api<ReviewSummary>("/reviews");

export const getPendingReviews = () =>
  api<{ count: number; items: PendingReviewItem[] }>("/reviews/pending").then(
    (r) => r.items
  );

export const flagForReview = (opts?: FlagOptions) =>
  api<{ flagged: number; total: number; pending_review: number }>(
    "/reviews/flag",
    {
      method: "POST",
      body: JSON.stringify(opts || {}),
    }
  );

export const submitReview = (data: ReviewSubmission) =>
  api<{
    success: boolean;
    scenario_id: string;
    final_result: string;
    final_confidence: number;
    total_reviews: number;
  }>("/reviews/submit", {
    method: "POST",
    body: JSON.stringify(data),
  });

export const exportReviews = () =>
  api<Record<string, unknown>>("/reviews/export");
