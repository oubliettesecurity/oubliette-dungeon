import { useParams } from "react-router-dom";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useApi } from "../hooks/useApi";
import {
  getSessionResults,
  getSessionSummary,
  getLatestSession,
} from "../api/client";

const COLORS: Record<string, string> = {
  detected: "#22c55e",
  bypass: "#ef4444",
  partial: "#f59e0b",
};

export default function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const isLatest = !id || id === "latest";

  const { data: latestSummary } = useApi(getLatestSession, []);
  const sessionId = isLatest ? latestSummary?.session_id ?? "" : id!;

  const { data: results, loading } = useApi(
    () => (sessionId ? getSessionResults(sessionId) : Promise.resolve([])),
    [sessionId]
  );
  const { data: summary } = useApi(
    () => (sessionId ? getSessionSummary(sessionId) : Promise.resolve(null)),
    [sessionId]
  );

  if (loading) return <p className="text-gray-500">Loading...</p>;
  if (!results || results.length === 0)
    return <p className="text-gray-500">No results found.</p>;

  const pieData = summary
    ? [
        { name: "Detected", value: summary.detected },
        { name: "Bypassed", value: summary.bypassed },
        { name: "Partial", value: summary.partial },
      ].filter((d) => d.value > 0)
    : [];

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Session: {sessionId}</h2>

      {summary && (
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-gray-900 rounded-lg p-4">
            <p className="text-sm text-gray-400 mb-1">Detection Rate</p>
            <p className="text-3xl font-bold">
              {(summary.detection_rate * 100).toFixed(1)}%
            </p>
          </div>
          <div className="bg-gray-900 rounded-lg p-4 flex items-center justify-center">
            <ResponsiveContainer width={180} height={180}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                >
                  {pieData.map((d, i) => (
                    <Cell
                      key={i}
                      fill={COLORS[d.name.toLowerCase()] ?? "#6b7280"}
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-gray-500 border-b border-gray-800">
            <th className="py-2 px-2">Scenario</th>
            <th className="py-2 px-2">Category</th>
            <th className="py-2 px-2">Difficulty</th>
            <th className="py-2 px-2">Result</th>
            <th className="py-2 px-2">Confidence</th>
            <th className="py-2 px-2">Time (ms)</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r) => (
            <tr
              key={r.scenario_id}
              className={`border-b border-gray-800/50 ${
                r.result === "bypass"
                  ? "bg-red-950/30"
                  : "hover:bg-gray-900"
              }`}
            >
              <td className="py-2 px-2">
                <span className="font-mono text-dungeon-400 mr-2">
                  {r.scenario_id}
                </span>
                {r.scenario_name}
              </td>
              <td className="py-2 px-2">{r.category}</td>
              <td className="py-2 px-2">{r.difficulty}</td>
              <td className="py-2 px-2">
                <ResultBadge result={r.result} />
              </td>
              <td className="py-2 px-2">
                {(r.confidence * 100).toFixed(0)}%
              </td>
              <td className="py-2 px-2">{r.execution_time_ms.toFixed(1)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ResultBadge({ result }: { result: string }) {
  const cls: Record<string, string> = {
    detected: "bg-green-900 text-green-300",
    bypass: "bg-red-900 text-red-300",
    partial: "bg-yellow-900 text-yellow-300",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${cls[result] ?? "bg-gray-800"}`}>
      {result}
    </span>
  );
}
