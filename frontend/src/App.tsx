import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AiDockProvider } from '@/contexts/AiDockContext'
import { Layout } from '@/components/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { Deploy } from '@/pages/Deploy'
import { Devices } from '@/pages/Devices'
import { DeviceDetail } from '@/pages/DeviceDetail'
import { Groups } from '@/pages/Groups'
import { Snapshots } from '@/pages/Snapshots'
import { Translations } from '@/pages/Translations'
import { Settings } from '@/pages/Settings'

const qc = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      {/* AiDockProvider must be inside QueryClientProvider so it can call useQueryClient() */}
      <AiDockProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="devices" element={<Devices />} />
              <Route path="devices/:name" element={<DeviceDetail />} />
              <Route path="groups" element={<Groups />} />
              <Route path="snapshots" element={<Snapshots />} />
              <Route path="translations" element={<Translations />} />
              <Route path="deploy" element={<Deploy />} />
              <Route path="settings" element={<Settings />} />
              {/* Legacy routes */}
              <Route path="policy" element={<Navigate to="/devices" replace />} />
              <Route path="chat" element={<Navigate to="/" replace />} />
              <Route path="diffs" element={<Navigate to="/snapshots" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AiDockProvider>
    </QueryClientProvider>
  )
}
