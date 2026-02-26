import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { getScenarios } from "../api/client";

export default function ScenarioLibrary() {
  const { data: scenarios, loading } = useApi(getScenarios);
  const [filter, setFilter] = useState("");
  const [catFilter, setCatFilter] = useState("");

  if (loading) return <p className="text-gray-500">Loading...</p>;
  if (!scenarios) return null;

  const categories = [...new Set(scenarios.map((s) => s.category))].sort();
  const filtered = scenarios.filter(
    (s) =>
      (!catFilter || s.category === catFilter) &&
      (!filter ||
        s.name.toLowerCase().includes(filter.toLowerCase()) ||
        s.id.toLowerCase().includes(filter.toLowerCase()))
  );

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Scenario Library</h2>
      <div className="flex gap-3">
        <input
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm flex-1"
          placeholder="Filter by name or ID..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <select
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
          value={catFilter}
          onChange={(e) => setCatFilter(e.target.value)}
        >
          <option value="">All Categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-gray-500 border-b border-gray-800">
            <th className="py-2 px-2">ID</th>
            <th className="py-2 px-2">Name</th>
            <th className="py-2 px-2">Category</th>
            <th className="py-2 px-2">Difficulty</th>
            <th className="py-2 px-2">Multi-turn</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((s) => (
            <tr
              key={s.id}
              className="border-b border-gray-800/50 hover:bg-gray-900"
            >
              <td className="py-2 px-2 font-mono text-dungeon-400">{s.id}</td>
              <td className="py-2 px-2">{s.name}</td>
              <td className="py-2 px-2">{s.category}</td>
              <td className="py-2 px-2">
                <DifficultyBadge d={s.difficulty} />
              </td>
              <td className="py-2 px-2">{s.multi_turn ? "Yes" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-xs text-gray-600">
        {filtered.length} of {scenarios.length} scenarios
      </p>
    </div>
  );
}

function DifficultyBadge({ d }: { d: string }) {
  const cls: Record<string, string> = {
    easy: "bg-green-900 text-green-300",
    medium: "bg-yellow-900 text-yellow-300",
    hard: "bg-red-900 text-red-300",
    advanced: "bg-purple-900 text-purple-300",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs ${cls[d] ?? "bg-gray-800 text-gray-400"}`}
    >
      {d}
    </span>
  );
}
