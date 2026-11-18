import { useQuery } from '@tanstack/react-query'
import { getPredictions } from '../lib/api'
import { formatTs } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'

export default function PredictionsPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['predictions'],
    queryFn: () => getPredictions({ limit: 100 }),
    refetchInterval: 5_000,
  })

  return (
    <>
      <TopBar title="Predictions" />
      <main className="p-6 space-y-6">
        {isLoading ? <PageSpinner /> : isError ? (
          <div className="text-red-400 text-sm">Failed to load predictions.</div>
        ) : (
          <Card>
            <CardHeader><CardTitle>Inference History</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-700">
                      {['Flow', 'Status', 'Raw Score', 'Model', 'Alerts', 'Created'].map(header =>
                        <th key={header} className="text-left pb-2 pr-4 font-medium">{header}</th>)}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {data?.map(prediction => (
                      <tr key={prediction.id}>
                        <td className="py-3 pr-4 font-mono text-slate-400">{prediction.flow_id.slice(0, 8)}...</td>
                        <td className="py-3 pr-4">
                          <Badge variant={prediction.status === 'ANOMALY' ? 'danger' : prediction.status === 'NORMAL' ? 'success' : 'muted'}>
                            {prediction.status}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4 text-slate-300">
                          {prediction.raw_score == null ? '-' : prediction.raw_score.toFixed(4)}
                        </td>
                        <td className="py-3 pr-4 font-mono text-slate-400">{prediction.model_version ?? '-'}</td>
                        <td className="py-3 pr-4 text-slate-300">{prediction.alerts_generated}</td>
                        <td className="py-3 text-slate-400">{formatTs(prediction.created_at)}</td>
                      </tr>
                    ))}
                    {data?.length === 0 && (
                      <tr><td colSpan={6} className="py-6 text-center text-slate-500">No predictions yet</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </>
  )
}
