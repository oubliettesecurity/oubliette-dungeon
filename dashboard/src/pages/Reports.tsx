import { useState } from "react";
import { useApi } from "../hooks/useApi";
import { getSessions, downloadPdf } from "../api/client";

export default function Reports() {
  const { data: sessions, loading } = useApi(getSessions);
  const [selected, setSelected] = useState("");
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    if (!selected) return;
    setDownloading(true);
    try {
      const blob = await downloadPdf(selected);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dungeon_${selected}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(false);
    }
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Reports</h2>
      <div className="bg-gray-900 rounded-lg p-6 space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Session</label>
          <select
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm w-full"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
          >
            <option value="">Select a session...</option>
            {sessions?.map((s) => (
              <option key={s.session_id} value={s.session_id}>
                {s.session_id} ({s.total_tests} tests)
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={handleDownload}
          disabled={!selected || downloading}
          className="px-4 py-2 bg-dungeon-600 hover:bg-dungeon-500 rounded text-sm font-medium disabled:opacity-50"
        >
          {downloading ? "Generating..." : "Download PDF Report"}
        </button>
      </div>
    </div>
  );
}
