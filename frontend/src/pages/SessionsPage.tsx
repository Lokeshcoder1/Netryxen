import { useQuery } from '@tanstack/react-query'
import { getSessions } from '../lib/api'
import { formatNumber, formatTs } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'

export default function SessionsPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => getSessions(0, 100),
  })

  return (
    <>
      <TopBar title="Capture Sessions" />
      <main className="p-6 space-y-6">
        {isLoading ? <PageSpinner /> : isError ? (
          <div className="text-red-400 text-sm">Failed to load sessions.</div>
        ) : (
          <Card>
            <CardHeader><CardTitle>Session History</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-700">
                      {['Session', 'Interface', 'Mode', 'Status', 'Packets', 'Started', 'Stopped'].map(header =>
                        <th key={header} className="text-left pb-2 pr-4 font-medium">{header}</th>)}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {data?.map(session => (
                      <tr key={session.id}>
                        <td className="py-3 pr-4 font-mono text-slate-400">{session.id.slice(0, 8)}...</td>
                        <td className="py-3 pr-4 text-slate-300">{session.interface_id}</td>
                        <td className="py-3 pr-4"><Badge variant={session.session_mode === 'BASELINE' ? 'info' : 'default'}>{session.session_mode}</Badge></td>
                        <td className="py-3 pr-4">
                          <Badge variant={session.status === 'RUNNING' ? 'success' : session.status === 'STOPPED' ? 'muted' : 'danger'}>
                            {session.status}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4 text-slate-300">{formatNumber(session.packets_seen)}</td>
                        <td className="py-3 pr-4 text-slate-400">{formatTs(session.started_at)}</td>
                        <td className="py-3 text-slate-400">{formatTs(session.stopped_at)}</td>
                      </tr>
                    ))}
                    {data?.length === 0 && (
                      <tr><td colSpan={7} className="py-6 text-center text-slate-500">No capture sessions</td></tr>
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
