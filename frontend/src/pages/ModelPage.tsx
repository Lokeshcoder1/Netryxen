import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrainCircuit, CheckCircle2, Database } from 'lucide-react'
import { getModelStatus, getSessions, trainBaseline } from '../lib/api'
import { formatTs } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Spinner, PageSpinner } from '../components/ui/Spinner'

export default function ModelPage() {
  const queryClient = useQueryClient()
  const [sessionId, setSessionId] = useState('')
  const [message, setMessage] = useState<string | null>(null)

  const statusQuery = useQuery({ queryKey: ['modelStatus'], queryFn: getModelStatus })
  const sessionsQuery = useQuery({ queryKey: ['sessions'], queryFn: () => getSessions(0, 100) })

  const trainMutation = useMutation({
    mutationFn: () => trainBaseline(sessionId),
    onSuccess: result => {
      setMessage(`Trained ${result.version} on ${result.training_sample_count} samples`)
      queryClient.invalidateQueries({ queryKey: ['modelStatus'] })
    },
    onError: (error: unknown) => {
      const detail = (error as { message?: string })?.message
      setMessage(detail ?? 'Training failed')
    },
  })

  if (statusQuery.isLoading || sessionsQuery.isLoading) return <><TopBar title="ML Model" /><PageSpinner /></>

  const status = statusQuery.data
  const model = status?.active_model
  const baselineSessions = sessionsQuery.data?.filter(session => session.session_mode === 'BASELINE') ?? []

  return (
    <>
      <TopBar title="ML Model" />
      <main className="p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { label: 'Model Status', value: status?.is_ready ? 'Ready' : 'Not Ready', icon: CheckCircle2 },
            { label: 'Registered Models', value: status?.total_registered_models ?? 0, icon: Database },
            { label: 'Algorithm', value: model?.algorithm ?? 'Not trained', icon: BrainCircuit },
          ].map(item => (
            <Card key={item.label} className="p-4">
              <div className="flex items-center gap-2 text-slate-400 text-xs uppercase"><item.icon className="w-4 h-4" />{item.label}</div>
              <p className="text-lg font-semibold text-slate-100 mt-2">{item.value}</p>
            </Card>
          ))}
        </div>

        {model && (
          <Card>
            <CardHeader><CardTitle>Active Model</CardTitle><Badge variant="success">{model.status}</Badge></CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div><p className="text-slate-500 text-xs">Version</p><p className="text-slate-200 font-mono mt-1">{model.version}</p></div>
                <div><p className="text-slate-500 text-xs">Training Samples</p><p className="text-slate-200 mt-1">{model.training_sample_count}</p></div>
                <div><p className="text-slate-500 text-xs">Features</p><p className="text-slate-200 mt-1">{model.feature_names.length}</p></div>
                <div><p className="text-slate-500 text-xs">Registered</p><p className="text-slate-200 mt-1">{formatTs(model.created_at)}</p></div>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader><CardTitle>Train Baseline Model</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <select
              className="w-full max-w-xl rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2"
              value={sessionId}
              onChange={event => setSessionId(event.target.value)}
            >
              <option value="">Select a completed baseline session</option>
              {baselineSessions.map(session => (
                <option key={session.id} value={session.id}>
                  {session.id.slice(0, 8)}... · {session.status} · {formatTs(session.started_at)}
                </option>
              ))}
            </select>
            <Button onClick={() => trainMutation.mutate()} disabled={!sessionId || trainMutation.isPending}>
              {trainMutation.isPending ? <Spinner className="h-4 w-4" /> : <BrainCircuit className="w-4 h-4" />}
              Train Baseline
            </Button>
            {message && <p className="text-sm text-slate-300">{message}</p>}
          </CardContent>
        </Card>
      </main>
    </>
  )
}
