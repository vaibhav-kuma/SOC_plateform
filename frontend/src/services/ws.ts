type MessageHandler = (data: any) => void

class WebSocketService {
  private ws: WebSocket | null = null
  private handlers: Map<string, MessageHandler[]> = new Map()
  private reconnectInterval = 5000
  private url: string = ''

  connect(token: string) {
    this.url = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws?token=${token}`
    this.createConnection()
  }

  private createConnection() {
    if (this.ws?.readyState === WebSocket.OPEN) return

    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      console.log('[WS] Connected')
    }

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        const handlers = this.handlers.get(data.type) || []
        handlers.forEach((handler) => handler(data.payload))
      } catch { /* ignore */ }
    }

    this.ws.onclose = () => {
      console.log('[WS] Disconnected, reconnecting...')
      setTimeout(() => this.createConnection(), this.reconnectInterval)
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  subscribe(type: string, handler: MessageHandler) {
    const existing = this.handlers.get(type) || []
    existing.push(handler)
    this.handlers.set(type, existing)
    return () => {
      const handlers = this.handlers.get(type)?.filter((h) => h !== handler)
      if (handlers?.length) this.handlers.set(type, handlers)
      else this.handlers.delete(type)
    }
  }

  disconnect() {
    this.ws?.close()
    this.ws = null
  }
}

export const wsService = new WebSocketService()
