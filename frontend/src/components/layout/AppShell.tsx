import TopBar from './TopBar'
import Sidebar from './Sidebar'
import StatusBar from './StatusBar'
import { cn } from '../../utils/cn'

interface AppShellProps {
  children: React.ReactNode
  rightPanel?: React.ReactNode
}

export default function AppShell({ children, rightPanel }: AppShellProps) {
  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-auto bg-soc-bg">
          {children}
        </main>
        {rightPanel && (
          <aside className="w-80 border-l border-soc-border bg-soc-sidebar overflow-y-auto shrink-0">
            {rightPanel}
          </aside>
        )}
      </div>
      <StatusBar />
    </div>
  )
}
