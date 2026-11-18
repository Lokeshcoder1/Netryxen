import { Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout'
import DashboardPage from './pages/DashboardPage'
import CapturePage from './pages/CapturePage'
import FlowsPage from './pages/FlowsPage'
import AlertsPage from './pages/AlertsPage'
import PredictionsPage from './pages/PredictionsPage'
import ModelPage from './pages/ModelPage'
import SessionsPage from './pages/SessionsPage'

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/capture" element={<CapturePage />} />
        <Route path="/flows" element={<FlowsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/predictions" element={<PredictionsPage />} />
        <Route path="/model" element={<ModelPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
