import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { ListParams, ListQueryOptions } from '@go-tangra/ui'
import { api, describe, type Note, type Page } from '@/api/client'

/** Sortable fields of GET /notes (server spec store::list_spec). */
export const NOTE_LIST: ListQueryOptions = { sortable: ['title', 'created_at', 'updated_at'], defaultSort: { key: 'created_at', dir: 'desc' }, defaultSize: 25 }

export const useNotes = defineStore('notes', () => {
  const items = ref<Note[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref('')
  let seq = 0

  /** Loads one page; resolves with it, or null when it failed or was superseded. */
  async function list(q: ListParams, search: string): Promise<Page<Note> | null> {
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const res = await api<Page<Note>>('GET', 'notes', undefined, { query: { ...q, q: search || undefined } })
      if (mine !== seq) return null
      items.value = res.items ?? []
      total.value = res.total ?? 0
      return res
    } catch (e) {
      if (mine === seq) error.value = describe(e)
      return null
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  async function create(title: string, body: string): Promise<Note> {
    return api<Note>('POST', 'notes', { title, body })
  }

  async function remove(id: string): Promise<void> {
    await api('POST', 'notes/' + id + '/remove')
    items.value = items.value.filter((n) => n.id !== id)
  }

  return { items, total, loading, error, list, create, remove }
})
