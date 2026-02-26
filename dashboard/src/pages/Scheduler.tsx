import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { getScheduleJobs, createScheduleJob } from "../api/client";

export default function Scheduler() {
  const { data: jobs, loading, refetch } = useApi(getScheduleJobs);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [cron, setCron] = useState("0 2 * * *");
  const [target, setTarget] = useState("http://localhost:5000/api/chat");

  const handleCreate = async () => {
    await createScheduleJob({ name, cron, target_url: target, enabled: true });
    setShowForm(false);
    setName("");
    refetch();
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Scheduler</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-4 py-2 bg-dungeon-600 hover:bg-dungeon-500 rounded text-sm font-medium"
        >
          {showForm ? "Cancel" : "New Job"}
        </button>
      </div>

      {showForm && (
        <div className="bg-gray-900 rounded-lg p-4 space-y-3">
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
            placeholder="Job name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono"
            placeholder="Cron expression"
            value={cron}
            onChange={(e) => setCron(e.target.value)}
          />
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
            placeholder="Target URL"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <button
            onClick={handleCreate}
            className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded text-sm"
          >
            Create
          </button>
        </div>
      )}

      {jobs && jobs.length > 0 ? (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="py-2 px-2">Name</th>
              <th className="py-2 px-2">Cron</th>
              <th className="py-2 px-2">Target</th>
              <th className="py-2 px-2">Enabled</th>
              <th className="py-2 px-2">Last Run</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr
                key={j.job_id}
                className="border-b border-gray-800/50 hover:bg-gray-900"
              >
                <td className="py-2 px-2">{j.name}</td>
                <td className="py-2 px-2 font-mono text-xs">{j.cron}</td>
                <td className="py-2 px-2 text-xs truncate max-w-xs">
                  {j.target_url}
                </td>
                <td className="py-2 px-2">{j.enabled ? "Yes" : "No"}</td>
                <td className="py-2 px-2 text-xs">{j.last_run ?? "Never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-gray-500 text-sm">No scheduled jobs yet.</p>
      )}
    </div>
  );
}
