// The notes API through the gateway: the kit client bound to this module's base.
import { createApi, ApiError, describe } from '@go-tangra/ui/api'

export { ApiError, describe }

export const BASE = '/api/notes/v1'
export const api = createApi({ base: BASE })

/** A note (api/openapi/notes.yaml, Note). */
export interface Note {
  id: string
  title: string
  body: string
  author_id: string
  created_at: string
  updated_at: string
}

/** One server page of a list endpoint (go-tangra list contract). */
export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  sort: string
  order: 'asc' | 'desc'
}
