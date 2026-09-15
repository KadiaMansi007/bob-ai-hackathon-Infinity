import axios from 'axios'

const api = axios.create({ baseURL: '/api/v1' })

export default api

// --- Dashboard ---
export const getDashboardStats = () => api.get('/dashboard/stats').then(r => r.data)

// --- Feeds ---
export const triggerFeedIngest = (scenario = 'random', seed?: number) =>
  api.post('/feeds/ingest', null, { params: { scenario, seed } }).then(r => r.data)
export const getFeedRuns = () => api.get('/feeds/runs').then(r => r.data)

// --- Alerts ---
export const getAlerts = (params?: Record<string, unknown>) =>
  api.get('/alerts', { params }).then(r => r.data)
export const getAlert = (id: string) => api.get(`/alerts/${id}`).then(r => r.data)
export const markAlertFP = (id: string, reason = 'manual_override') =>
  api.patch(`/alerts/${id}/fp`, null, { params: { fp_reason: reason } }).then(r => r.data)

// --- Incidents ---
export const getIncidents = (params?: Record<string, unknown>) =>
  api.get('/incidents', { params }).then(r => r.data)
export const getIncident = (id: string) => api.get(`/incidents/${id}`).then(r => r.data)
export const getIncidentClassification = (id: string) =>
  api.get(`/incidents/${id}/classification`).then(r => r.data)
export const getIncidentGraph = (id: string) =>
  api.get(`/incidents/${id}/graph`).then(r => r.data)
export const updateIncidentStatus = (id: string, status: string) =>
  api.patch(`/incidents/${id}/status`, null, { params: { status } }).then(r => r.data)

// --- Bob ---
export const analyseWithBob = (incidentId: string) =>
  api.post(`/bob/analyse/${incidentId}`).then(r => r.data)
export const getBobAnalysis = (incidentId: string) =>
  api.get(`/bob/analysis/${incidentId}`).then(r => r.data)
export const generateBluf = (incidentId: string) =>
  api.post(`/bob/bluf/${incidentId}`).then(r => r.data)
export const getBluf = (incidentId: string) =>
  api.get(`/bob/bluf/${incidentId}`).then(r => r.data)

// --- MITRE ---
export const getMitreMatrix = () => api.get('/mitre/matrix').then(r => r.data)
