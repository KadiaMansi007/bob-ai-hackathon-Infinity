import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import AlertFeed from './pages/AlertFeed'
import AlertDetail from './pages/AlertDetail'
import IncidentList from './pages/IncidentList'
import IncidentDetail from './pages/IncidentDetail'
import MitreMatrix from './pages/MitreMatrix'
import BlufSummary from './pages/BlufSummary'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts" element={<AlertFeed />} />
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/incidents" element={<IncidentList />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/incidents/:id/bluf" element={<BlufSummary />} />
        <Route path="/mitre" element={<MitreMatrix />} />
      </Routes>
    </Layout>
  )
}
