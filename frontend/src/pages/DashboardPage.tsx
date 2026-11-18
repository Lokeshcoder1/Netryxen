// src/pages/DashboardPage.tsx
import { useQuery } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie,
} from 'recharts'
import {
  Activity, Waves, ShieldAlert, Server,
  ArrowUpRight, ArrowDownRight, BrainCircuit, Cpu,
} from 'lucide-react'
import { getDashboard } from '../lib/api'
import { formatBytes, formatNumber } from '../lib/utils'
import { StatTile } from '../components/ui/StatTile'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { TopBar } from '../components/layout/TopBar'

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

const PROTO_COLORS = ['#38bdf8', '#818cf8', '#34d399', '#fb923c', '#f472b6', '#a78bfa']

export default function DashboardPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['dashboard'],
    queryFn: getDashboard,
    refetchInterval: 5_000,
  })

  if (isLoading) return <><TopBar title="Dashboard" /><PageSpinner /></>
  if (isError || !data) return (
    <><TopBar title="Dashboard" />
    <div className="p-6 text-red-400">Failed to load dashboard. Is the backend running?</div>
    </>
  )

  const alertBar = [
    { name: 'CRITICAL', value: data.alert_summary.critical },
    { name: 'HIGH',     value: data.alert_summary.high },
    { name: 'MEDIUM',   value: data.alert_summary.medium },
    { name: 'LOW',      value: data.alert_summary.low },
  ].filter(x => x.value > 0)

  const protoPie = Object.entries(data.protocol_distribution).map(([name, value]) => ({ name, value }))

  return (
    <>
      <TopBar title="Dashboard" />
      <main className="p-6 space-y-6">

        {/* Stat tiles row 1 */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatTile label="Total Flows" value={formatNumber(data.total_flows)} icon={Waves} accent="sky" />
          <StatTile label="Sessions" value={data.total_sessions} icon={Server} accent="violet" />
          <StatTile label="Traffic" value={formatBytes(data.total_bytes)} icon={Activity} accent="emerald"
            sub={`${formatNumber(data.total_packets)} packets observed`} />
          <StatTile label="Open Alerts" value={data.alert_summary.total_open} icon={ShieldAlert} accent="red" />
        </div>

        {/* Stat tiles row 2 — detection worker */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatTile label="Jobs Completed" value={formatNumber(data.detection_worker.completed_jobs)} icon={BrainCircuit} accent="emerald" />
          <StatTile label="Jobs Pending" value={data.detection_worker.pending_jobs} icon={Cpu} accent="amber"
            sub={`processing: ${data.detection_worker.processing_jobs}`} />
          <StatTile label="Jobs Failed" value={data.detection_worker.failed_jobs} icon={Cpu} accent="red" />
          <StatTile label="Worker Processed" value={formatNumber(data.detection_worker.total_processed)} icon={Activity} accent="sky" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Alert severity distribution */}
          <Card>
            <CardHeader><CardTitle>Alert Severity</CardTitle></CardHeader>
            <CardContent>
              {alertBar.length === 0
                ? <p className="text-slate-500 text-sm">No open alerts 🎉</p>
                : (
                  <ResponsiveContainer width="100%" height={160}>
                    <BarChart data={alertBar} barSize={28}>
                      <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                      <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12 }} />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {alertBar.map(e => <Cell key={e.name} fill={SEVERITY_COLOR[e.name]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
            </CardContent>
          </Card>

          {/* Protocol distribution */}
          <Card>
            <CardHeader><CardTitle>Protocol Mix</CardTitle></CardHeader>
            <CardContent>
              {protoPie.length === 0
                ? <p className="text-slate-500 text-sm">No flows yet</p>
                : (
                  <ResponsiveContainer width="100%" height={160}>
                    <PieChart>
                      <Pie data={protoPie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60}
                        label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                        labelLine={false}>
                        {protoPie.map((_, i) => <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                )}
            </CardContent>
          </Card>

          {/* Top talkers */}
          <Card>
            <CardHeader><CardTitle>Top Talkers</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                {data.top_talkers.slice(0, 8).map(t => (
                  <div key={t.ip} className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono text-slate-300 truncate">{t.ip}</span>
                    <div className="flex items-center gap-3 text-slate-400 shrink-0">
                      <span className="flex items-center gap-1 text-sky-400">
                      <ArrowUpRight className="w-3 h-3" />{formatBytes(t.bytes_sent)}
                      </span>
                      <span className="flex items-center gap-1 text-violet-400">
                      <ArrowDownRight className="w-3 h-3" />{formatBytes(t.bytes_recv)}
                      </span>
                    </div>
                  </div>
                ))}
                {data.top_talkers.length === 0 && <p className="text-slate-500 text-sm">No traffic yet</p>}
              </div>
            </CardContent>
          </Card>

        </div>

        {/* Recent flows */}
        <Card>
          <CardHeader><CardTitle>Recent Flows</CardTitle></CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-slate-700">
                  {['Source', 'Destination', 'Protocol', 'Packets', 'Bytes', 'Last Seen'].map(h => (
                    <th key={h} className="text-left pb-2 pr-4 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {data.recent_flows.map(flow => (
                  <tr key={flow.id}>
                    <td className="py-2 pr-4 font-mono text-slate-300">{flow.src_ip ?? '—'}:{flow.src_port ?? '—'}</td>
                    <td className="py-2 pr-4 font-mono text-slate-300">{flow.dst_ip ?? '—'}:{flow.dst_port ?? '—'}</td>
                    <td className="py-2 pr-4"><Badge variant="info">{flow.protocol}</Badge></td>
                    <td className="py-2 pr-4 text-slate-300">{formatNumber(flow.packet_count)}</td>
                    <td className="py-2 pr-4 text-slate-300">{formatBytes(flow.byte_count)}</td>
                    <td className="py-2 text-slate-400">{new Date(flow.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
                {data.recent_flows.length === 0 && (
                  <tr><td colSpan={6} className="py-4 text-slate-500">No flows yet</td></tr>
                )}
              </tbody>
            </table>
            </div>
          </CardContent>
        </Card>

      </main>
    </>
  )
}
