import { create } from 'zustand'
import type { Alert, DashboardStats, Incident } from '../types'
import api from '../services/api'

interface AlertState {
  alerts: Alert[]
  incidents: Incident[]
  stats: DashboardStats | null
  loading: boolean
  error: string | null
  fetchAlerts: () => Promise<void>
  fetchIncidents: () => Promise<void>
  fetchStats: () => Promise<void>
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  incidents: [],
  stats: null,
  loading: false,
  error: null,

  fetchAlerts: async () => {
    set({ loading: true })
    try {
      const { data } = await api.get('/alerts', { params: { page_size: 50 } })
      set({ alerts: data, loading: false })
    } catch (err: any) {
      set({ error: err.message, loading: false })
    }
  },

  fetchIncidents: async () => {
    try {
      const { data } = await api.get('/incidents', { params: { page_size: 20 } })
      set({ incidents: data })
    } catch { /* ignore */ }
  },

  fetchStats: async () => {
    try {
      const { data } = await api.get('/dashboard/summary')
      set({ stats: data })
    } catch { /* ignore */ }
  },
}))
