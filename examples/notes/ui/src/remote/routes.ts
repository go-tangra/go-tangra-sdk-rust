import type { RouteRecordRaw } from 'vue-router'
import '@/main.css'

// Routes mounted by the platform shell under their own error boundary.
export const routes: RouteRecordRaw[] = [
  { path: '/notes', name: 'notes-list', component: () => import('@/views/notes/index.vue'), meta: { module: 'notes' } },
]
export default routes
