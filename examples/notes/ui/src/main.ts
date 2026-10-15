// Standalone development entry: mounts the notes routes in a bare kit shell
// against the gateway (npm run dev). In the platform the shell mounts
// ./routes and ./nav from the federated remote instead.
import { createApp, h } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory, RouterView } from 'vue-router'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'
import { UiAppShell } from '@go-tangra/ui'
import './dev.css'
import { routes } from '@/remote/routes'

const app = createApp({ render: () => h(UiAppShell, { title: 'notes (dev)', hideNav: true }, () => h(RouterView)) })
app.use(createPinia())
app.use(createRouter({ history: createWebHistory('/'), routes }))
app.use(abilitiesPlugin, createMongoAbility([{ action: 'manage', subject: 'all' }]), { useGlobalProperties: true })
app.mount('#app')
