import { Routes, Route, NavLink } from "react-router-dom";
import CommandCenter from "./pages/CommandCenter";
import ScenarioLibrary from "./pages/ScenarioLibrary";
import SessionDetail from "./pages/SessionDetail";
import ProviderComparison from "./pages/ProviderComparison";
import Scheduler from "./pages/Scheduler";
import Reports from "./pages/Reports";

const NAV = [
  { to: "/", label: "Command Center" },
  { to: "/scenarios", label: "Scenarios" },
  { to: "/sessions/latest", label: "Latest Session" },
  { to: "/providers", label: "Providers" },
  { to: "/scheduler", label: "Scheduler" },
  { to: "/reports", label: "Reports" },
];

export default function App() {
  return (
    <div className="flex h-screen">
      <nav className="w-56 bg-gray-900 border-r border-gray-800 p-4 flex flex-col gap-1">
        <h1 className="text-lg font-bold text-dungeon-400 mb-4">
          Oubliette Dungeon
        </h1>
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === "/"}
            className={({ isActive }) =>
              `px-3 py-2 rounded text-sm ${
                isActive
                  ? "bg-dungeon-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800"
              }`
            }
          >
            {n.label}
          </NavLink>
        ))}
      </nav>
      <main className="flex-1 overflow-auto p-6">
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/scenarios" element={<ScenarioLibrary />} />
          <Route path="/sessions/:id" element={<SessionDetail />} />
          <Route path="/sessions/latest" element={<SessionDetail />} />
          <Route path="/providers" element={<ProviderComparison />} />
          <Route path="/scheduler" element={<Scheduler />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
    </div>
  );
}
