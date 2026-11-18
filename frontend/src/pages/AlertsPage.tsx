import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getAlerts, updateAlertStatus, type AlertStatus } from '../lib/api'
import { formatTs } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { PageSpinner } from '../components/ui/Spinner'

export default function AlertsPage() {
  const queryClient = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['alerts', severity, status],
    queryFn: () => getAlerts({
      ...(severity ? { severity } : {}),
      ...(status ? { status } : {}),
      limit: 100,
    }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, target }: { id: string; target: AlertStatus }) =>
      updateAlertStatus(id, target),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const severityVariant = (value: string) => {
    if (value === 'CRITICAL') return 'danger'
    if (value === 'HIGH') return 'warning'
    if (value === 'MEDIUM') return 'info'
    return 'success'
  }

  return (
    <>
      <TopBar title="Security Alerts" />
      <main className="p-6 space-y-6">
        <Card><CardContent className="pt-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <select className="rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2"
              value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="">All severities</option>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(value => <option key={value}>{value}</option>)}
            </select>
            <select className="rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2"
              value={status} onChange={event => setStatus(event.target.value)}>
              <option value="">All statuses</option>
              {['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'].map(value => <option key={value}>{value}</option>)}
            </select>
          </div>
        </CardContent></Card>

        {isLoading ? <PageSpinner /> : isError ? (
          <div className="text-red-400 text-sm">Failed to load alerts.</div>
        ) : (
          <div className="space-y-3">
            {data?.map(alert => (
              <Card key={alert.id}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Badge variant={severityVariant(alert.severity)}>{alert.severity}</Badge>
                    <Badge variant={alert.status === 'OPEN' ? 'danger' : 'muted'}>{alert.status}</Badge>
                  </div>
                  <Badge variant="info">{alert.detection_source}</Badge>
                </CardHeader>
                <CardContent>
                  <h3 className="text-sm font-semibold text-slate-100">{alert.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{alert.description}</p>
                  <div className="flex flex-wrap items-center justify-between gap-3 mt-4">
                    <p className="text-xs text-slate-500">
                      Occurrences: {alert.occurrence_count} · Last seen: {formatTs(alert.last_seen)}
                    </p>
                    {alert.status !== 'RESOLVED' && alert.status !== 'FALSE_POSITIVE' && (
                      <div className="flex gap-2">
                        {alert.status === 'OPEN' && (
                          <Button size="sm" variant="ghost"
                            disabled={updateMutation.isPending}
                            onClick={() => updateMutation.mutate({ id: alert.id, target: 'ACKNOWLEDGED' })}>
                            Acknowledge
                          </Button>
                        )}
                        <Button size="sm" variant="success"
                          disabled={updateMutation.isPending}
                          onClick={() => updateMutation.mutate({ id: alert.id, target: 'RESOLVED' })}>
                          Resolve
                        </Button>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
            {data?.length === 0 && <Card><CardContent className="pt-5 text-sm text-slate-500">No alerts found.</CardContent></Card>}
          </div>
        )}
      </main>
    </>
  )
}
