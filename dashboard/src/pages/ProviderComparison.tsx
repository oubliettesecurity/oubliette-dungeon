export default function ProviderComparison() {
  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Provider Comparison</h2>
      <div className="bg-gray-900 rounded-lg p-8 text-center text-gray-500">
        <p className="text-lg mb-2">Multi-Provider Comparison</p>
        <p className="text-sm">
          Run red team scenarios against multiple LLM providers and compare
          results side-by-side.
        </p>
        <p className="text-sm mt-4 text-gray-600">
          Configure providers via the API or CLI to enable comparisons.
        </p>
      </div>
    </div>
  );
}
