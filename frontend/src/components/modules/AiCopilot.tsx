import { useState, useRef, useEffect } from 'react'
import type { ChatMessage, Action } from '../../types'

const SUGGESTIONS = [
  'Investigate latest critical alert',
  'Show lateral movement in last 24h',
  'Summarize current security posture',
  'What vulnerabilities affect DC-01?',
]

const QUICK_ACTIONS: Action[] = [
  { label: 'Isolate Endpoint', action: 'isolate', severity: 'critical' },
  { label: 'Block IP', action: 'block_ip', severity: 'high' },
  { label: 'Generate Report', action: 'report', severity: 'info' },
]

export default function AiCopilot() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: "Hello, I'm your AI Security Copilot. I can investigate alerts, analyze threats, and recommend actions. How can I help?",
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const sendMessage = async (text: string) => {
    if (!text.trim() || loading) return

    const userMsg: ChatMessage = { role: 'user', content: text }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const token = localStorage.getItem('access_token')
      const res = await fetch('/api/v1/copilot/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ message: text }),
      })
      const data = await res.json()
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.response },
      ])
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'Sorry, I encountered an error. Please try again.' },
      ])
    }
    setLoading(false)
  }

  return (
    <div className="flex flex-col h-full">
      <div className="panel-header shrink-0">
        <span>🤖 AI Security Copilot</span>
        <span className="ml-auto text-2xs text-green-400">● Online</span>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="w-6 h-6 rounded-full bg-soc-accent/20 flex items-center justify-center text-xs shrink-0 mt-1">
                🤖
              </div>
            )}
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-xs leading-relaxed ${
                msg.role === 'user'
                  ? 'bg-soc-accent/10 text-soc-accent'
                  : 'bg-soc-surface border border-soc-border text-soc-text'
              }`}
            >
              {msg.content.split('\n').map((line, j) => (
                <p key={j} className={line.startsWith('##') ? 'text-sm font-bold mt-2 mb-1' : line.startsWith('-') ? 'ml-2' : ''}>
                  {line || <br />}
                </p>
              ))}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex gap-2">
            <div className="w-6 h-6 rounded-full bg-soc-accent/20 flex items-center justify-center shrink-0">
              🤖
            </div>
            <div className="bg-soc-surface border border-soc-border rounded-lg px-3 py-2">
              <div className="flex gap-1">
                <div className="w-1.5 h-1.5 bg-soc-accent rounded-full animate-bounce" />
                <div className="w-1.5 h-1.5 bg-soc-accent rounded-full animate-bounce [animation-delay:0.1s]" />
                <div className="w-1.5 h-1.5 bg-soc-accent rounded-full animate-bounce [animation-delay:0.2s]" />
              </div>
            </div>
          </div>
        )}

        {messages.length === 1 && (
          <div className="space-y-1.5 mt-3">
            <p className="text-2xs text-soc-text-dim mb-2">Suggestions:</p>
            {SUGGESTIONS.map((s, i) => (
              <button
                key={i}
                onClick={() => sendMessage(s)}
                className="block w-full text-left text-xs text-soc-accent bg-soc-accent/5 border border-soc-accent/20 rounded px-2 py-1.5 hover:bg-soc-accent/10 transition-colors"
              >
                {s}
              </button>
            ))}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <div className="shrink-0 border-t border-soc-border p-2 space-y-2">
        <div className="flex gap-1">
          {QUICK_ACTIONS.map((action) => (
            <button
              key={action.action}
              className={`flex-1 text-2xs py-1 rounded font-medium ${
                action.severity === 'critical'
                  ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                  : action.severity === 'high'
                  ? 'bg-orange-500/20 text-orange-400 hover:bg-orange-500/30'
                  : 'bg-soc-accent/10 text-soc-accent hover:bg-soc-accent/20'
              }`}
            >
              {action.label}
            </button>
          ))}
        </div>

        <div className="flex gap-2">
          <input
            className="input flex-1 text-xs"
            placeholder="Ask the AI Copilot..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendMessage(input)}
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={loading || !input.trim()}
            className="btn-primary px-2"
          >
            Send
          </button>
        </div>
      </div>
    </div>
  )
}
