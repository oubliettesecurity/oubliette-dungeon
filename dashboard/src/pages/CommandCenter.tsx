import { useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { useApi } from "../hooks/useApi";
import {
  getLatestSession,
  getScenarioStats,
  startSession,
} from "../api/client";

const COLORS: Record<string, string> = {
  detected: "#22c55e",
  bypass: "#ef4444",
  partial: "#f59e0b",
  error: "#6b7280",
};

export default function CommandCenter() {
  const {
    data: summary,
    loading,
    refetch,
  } = useApi(getLatestSession);
  const { data: stats } = useApi(getScenarioStats);
  const [running, setRunning] = useState(false);

  const handleRun = async () => {
    setRunning(true);
    try {
      await startSession();
      setTimeout(refetch, 2000);
    } finally {
      setRunning(false);
    }
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;
  if (!summary) return <p className="text-gray-500">No sessions yet.</p>;

  const chartData = [
    { name: "Detected", value: summary.detected, color: COLORS.detected },
    { name: "Bypassed", value: summary.bypassed, color: COLORS.bypass },
    { name: "Partial", value: summary.partial, color: COLORS.partial },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Command Center</h2>
        <button
          onClick={handleRun}
          disabled={running}
          className="px-4 py-2 bg-dungeon-600 hover:bg-dungeon-500 rounded font-medium disabled:opacity-50"
        >
          {running ? "Running..." : "Run Session"}
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <KPI label="Total Scenarios" value={summary.total} />
        <KPI
          label="Detection Rate"
          value={`${(summary.detection_rate * 100).toFixed(1)}%`}
        />
        <KPI
          label="Bypasses"
          value={summary.bypassed}
          alert={summary.bypassed > 0}
        />
        <KPI
          label="Library Size"
          value={
            stats
              ? (stats as Record<string, number>).total ?? "..."
              : "..."
          }
        />
      </div>

      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-400 mb-3">
          Results Breakdown
        </h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={chartData}>
            <XAxis dataKey="name" stroke="#9ca3af" />
            <YAxis stroke="#9ca3af" />
            <Tooltip />
            <Bar dataKey="value">
              {chartData.map((d, i) => (
                <Cell key={i} fill={d.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function KPI({
  label,
  value,
  alert,
}: {
  label: string;
  value: string | number;
  alert?: boolean;
}) {
  return (
    <div
      className={`bg-gray-900 rounded-lg p-4 ${alert ? "border border-red-500" : ""}`}
    >
      <p className="text-xs text-gray-500 uppercase">{label}</p>
      <p
        className={`text-2xl font-bold ${alert ? "text-red-400" : "text-white"}`}
      >
        {value}
      </p>
    </div>
  );
}
