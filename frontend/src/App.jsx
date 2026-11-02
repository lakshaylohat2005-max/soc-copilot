import React, { useState, useEffect, useRef } from "react"
import { Shield, AlertTriangle, Terminal, Zap, Radio, CheckCircle, Database } from "lucide-react"

export default function App() {
  const [backendStatus, setBackendStatus] = useState("Checking...")
  const [wsConnected, setWsConnected] = useState(false)
  const reconnectTimeoutRef = useRef(null)

  useEffect(() => {
    // 1. Health check poller
    const checkHealth = () => {
      fetch("/api/health")
        .then((res) => {
          if (!res.ok) throw new Error("HTTP error")
          return res.json()
        })
        .then((data) => setBackendStatus(data.status === "healthy" ? "Online" : "Unknown"))
        .catch(() => setBackendStatus("Offline"))
    }

    checkHealth()
    const healthInterval = setInterval(checkHealth, 5000)

    // 2. Resilient WebSocket with auto-reconnect
    let ws = null
    const connectWS = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
      ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

      ws.onopen = () => {
        setWsConnected(true)
      }

      ws.onclose = () => {
        setWsConnected(false)
        // Attempt reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(connectWS, 3000)
      }

      ws.onerror = () => {
        setWsConnected(false)
        ws.close()
      }
    }

    connectWS()

    return () => {
      clearInterval(healthInterval)
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current)
      if (ws) ws.close()
    }
  }, [])

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F17] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#111827]/70 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              SOC Copilot
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Hackathon Edition
              </span>
            </h1>
            <p className="text-xs text-gray-400">Autonomous Incident Correlation & Response</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs px-3 py-1.5 rounded-md bg-gray-800/80 border border-gray-700">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? "text-emerald-400 animate-pulse" : "text-gray-500"}`} />
            <span className="text-gray-400">Live WS:</span>
            <span className={wsConnected ? "text-emerald-400 font-medium" : "text-gray-400"}>
              {wsConnected ? "Connected" : "Disconnected"}
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs px-3 py-1.5 rounded-md bg-gray-800/80 border border-gray-700">
            <CheckCircle className={`w-3.5 h-3.5 ${backendStatus === "Online" ? "text-emerald-400" : "text-rose-400"}`} />
            <span className="text-gray-400">API:</span>
            <span className={backendStatus === "Online" ? "text-emerald-400 font-medium" : "text-rose-400"}>
              {backendStatus}
            </span>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="flex-1 p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-sm">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs uppercase tracking-wider font-semibold">Ingested Logs</span>
              <Database className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
            <div className="text-xs text-gray-500 mt-1">Awaiting simulator feed</div>
          </div>

          <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-sm">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs uppercase tracking-wider font-semibold">Triggered Alerts</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
            <div className="text-xs text-gray-500 mt-1">YAML rule detections</div>
          </div>

          <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-sm">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs uppercase tracking-wider font-semibold">Active Incidents</span>
              <Terminal className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
            <div className="text-xs text-gray-500 mt-1">Correlated multi-stage attacks</div>
          </div>

          <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-sm">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs uppercase tracking-wider font-semibold">Actions Executed</span>
              <Zap className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
            <div className="text-xs text-gray-500 mt-1">1-click mitigation actions</div>
          </div>
        </div>

        {/* Scaffold Placeholder View */}
        <div className="p-8 rounded-2xl bg-gray-900/60 border border-gray-800 text-center space-y-3">
          <div className="inline-flex p-3 bg-blue-500/10 text-blue-400 rounded-full mb-1">
            <Shield className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-semibold text-white">SOC Copilot Initialized</h2>
          <p className="text-sm text-gray-400 max-w-xl mx-auto">
            Backend models, database session, health endpoints, WebSocket connection, and Tailwind frontend scaffold are configured and ready.
          </p>
        </div>
      </main>
    </div>
  )
}
