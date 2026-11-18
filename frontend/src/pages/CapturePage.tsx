// src/pages/CapturePage.tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Radio, Square, Wifi } from 'lucide-react'
import {
  getInterfaces, getCaptureStatus, startCapture, stopCapture,
} from '../lib/api'
import { formatNumber } from '../lib/utils'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Spinner, PageSpinner } from '../components/ui/Spinner'

export default function CapturePage() {
  const qc = useQueryClient()
  const [selectedIface, setSelectedIface] = useState<string>('')
  const [mode, setMode] = useState<'BASELINE' | 'MONITORING'>('MONITORING')
  const [bpf, setBpf] = useState('')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const { data: interfaces, isLoading: ifaceLoading } = useQuery({
    queryKey: ['interfaces'],
    queryFn: getInterfaces,
  })

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['captureStatus'],
    queryFn: getCaptureStatus,
    refetchInterval: 2_000,
  })

  const startMut = useMutation({
    mutationFn: () => startCapture({ interface_id: selectedIface, session_mode: mode, bpf_filter: bpf || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['captureStatus'] }); setErrorMsg(null) },
    onError: (error: unknown) => {
      const detail = (error as { message?: string })?.message
      setErrorMsg(detail ?? 'Start failed')
    },
  })

  const stopMut = useMutation({
    mutationFn: stopCapture,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['captureStatus'] }); qc.invalidateQueries({ queryKey: ['dashboard'] }) },
    onError: (error: unknown) => {
      const detail = (error as { message?: string })?.message
      setErrorMsg(detail ?? 'Stop failed')
    },
  })

  if (ifaceLoading || statusLoading) return <><TopBar title="Capture" /><PageSpinner /></>

  const isRunning = status?.is_running ?? false

  return (
    <>
      <TopBar title="Capture Control" />
      <main className="p-6 space-y-6">

        {/* Live status */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Status', value: isRunning ? 'RUNNING' : 'STOPPED' },
            { label: 'Packets Seen', value: formatNumber(status?.packets_seen ?? 0) },
            { label: 'Enqueued', value: formatNumber(status?.packets_enqueued ?? 0) },
            { label: 'Dropped', value: formatNumber(status?.packets_dropped ?? 0) },
          ].map(s => (
            <Card key={s.label} className="p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">{s.label}</p>
              <p className={`text-xl font-bold mt-1 ${s.label === 'Status' ? (isRunning ? 'text-emerald-400' : 'text-slate-400') : (s.label === 'Dropped' && parseInt(s.value) > 0 ? 'text-red-400' : 'text-slate-100')}`}>
                {s.value}
              </p>
            </Card>
          ))}
        </div>

        {status?.active_session_id && (
          <div className="text-xs text-slate-500 font-mono">
            Session: {status.active_session_id} · Interface: {status.interface_id} · Mode: {status.session_mode}
          </div>
        )}

        {errorMsg && (
          <div className="rounded-lg border border-red-700/50 bg-red-900/20 px-4 py-3 text-sm text-red-300">
            {errorMsg}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* Start capture */}
          <Card>
            <CardHeader><CardTitle>Start Capture</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Network Interface</label>
                <select
                  className="w-full rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-600"
                  value={selectedIface}
                  onChange={e => setSelectedIface(e.target.value)}
                  disabled={isRunning}
                >
                  <option value="">— Select interface —</option>
                  {interfaces?.filter(i => !i.is_loopback).map(i => (
                    <option key={i.id} value={i.id}>
                      {i.name}{i.ip_addresses.length > 0 ? ` (${i.ip_addresses[0]})` : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 mb-1 block">Session Mode</label>
                <div className="flex gap-2">
                  {(['MONITORING', 'BASELINE'] as const).map(m => (
                    <button
                      key={m}
                      onClick={() => setMode(m)}
                      disabled={isRunning}
                      className={`flex-1 rounded-lg py-2 text-sm font-medium border transition-colors disabled:opacity-40 ${
                        mode === m
                          ? 'bg-sky-600 border-sky-500 text-white'
                          : 'bg-slate-700 border-slate-600 text-slate-300 hover:bg-slate-600'
                      }`}
                    >{m}</button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-400 mb-1 block">BPF Filter (optional)</label>
                <input
                  className="w-full rounded-lg bg-slate-700 border border-slate-600 text-slate-200 text-sm px-3 py-2 font-mono focus:outline-none focus:ring-2 focus:ring-sky-600"
                  placeholder="e.g. ip or ip6"
                  value={bpf}
                  onChange={e => setBpf(e.target.value)}
                  disabled={isRunning}
                />
              </div>

              <div className="flex gap-3 pt-1">
                <Button
                  onClick={() => startMut.mutate()}
                  disabled={isRunning || !selectedIface || startMut.isPending}
                >
                  {startMut.isPending ? <Spinner className="h-4 w-4" /> : <Radio className="w-4 h-4" />}
                  Start Capture
                </Button>
                <Button
                  variant="danger"
                  onClick={() => stopMut.mutate()}
                  disabled={!isRunning || stopMut.isPending}
                >
                  {stopMut.isPending ? <Spinner className="h-4 w-4" /> : <Square className="w-4 h-4" />}
                  Stop
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Interface list */}
          <Card>
            <CardHeader><CardTitle>Available Interfaces</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {interfaces?.map(iface => (
                  <div key={iface.id}
                    className={`rounded-lg border p-3 cursor-pointer transition-colors ${
                      selectedIface === iface.id
                        ? 'border-sky-600 bg-sky-900/20'
                        : 'border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => !isRunning && !iface.is_loopback && setSelectedIface(iface.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Wifi className="w-4 h-4 text-slate-400 shrink-0" />
                        <span className="text-sm text-slate-200 font-medium">{iface.name}</span>
                      </div>
                      <Badge variant={iface.status === 'Up' ? 'success' : 'muted'}>{iface.status}</Badge>
                    </div>
                    {iface.ip_addresses.length > 0 && (
                      <p className="text-xs text-slate-500 font-mono mt-1 ml-6">
                        {iface.ip_addresses.slice(0, 2).join(', ')}
                      </p>
                    )}
                    {iface.is_loopback && <p className="text-xs text-slate-600 ml-6 mt-0.5">loopback</p>}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

        </div>
      </main>
    </>
  )
}
