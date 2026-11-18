import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { getFlows } from '../lib/api'
import { formatBytes, formatNumber, formatTs } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'

export default function FlowsPage() {
  const [protocol, setProtocol] = useState('')
  const [ip, setIp] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['flows', protocol, ip],
    queryFn: () => getFlows({
      ...(protocol ? { protocol } : {}),
      ...(ip ? { ip } : {}),
      limit: 100,
    }),
    refetchInterval: 5_000,
  })

  return (
    <>
      <TopBar title="Network Flows" />
      <main className="p-6 space-y-6">
        <Card>
          <CardContent className="pt-5">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <select
                className="rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2"
                value={protocol}
                onChange={event => setProtocol(event.target.value)}
              >
                <option value="">All protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
              <div className="relative md:col-span-2">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  className="w-full rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm pl-9 pr-3 py-2"
                  placeholder="Filter by source or destination IP"
                  value={ip}
                  onChange={event => setIp(event.target.value)}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {isLoading ? <PageSpinner /> : isError ? (
          <div className="text-red-400 text-sm">Failed to load flows.</div>
        ) : (
          <Card>
            <CardHeader><CardTitle>Flow Records</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-700">
                      {['Source', 'Destination', 'Protocol', 'Packets', 'Bytes', 'Window'].map(header => (
                        <th key={header} className="text-left pb-2 pr-4 font-medium">{header}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {data?.map(flow => (
                      <tr key={flow.id}>
                        <td className="py-3 pr-4 font-mono text-slate-300">{flow.src_ip}:{flow.src_port ?? '-'}</td>
                        <td className="py-3 pr-4 font-mono text-slate-300">{flow.dst_ip}:{flow.dst_port ?? '-'}</td>
                        <td className="py-3 pr-4"><Badge variant="info">{flow.protocol}</Badge></td>
                        <td className="py-3 pr-4 text-slate-300">{formatNumber(flow.packet_count)}</td>
                        <td className="py-3 pr-4 text-slate-300">{formatBytes(flow.byte_count)}</td>
                        <td className="py-3 text-slate-400">{formatTs(flow.window_start)}</td>
                      </tr>
                    ))}
                    {data?.length === 0 && (
                      <tr><td colSpan={6} className="py-6 text-center text-slate-500">No matching flows</td></tr>
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
