<script setup lang="ts">
// The tenant's notes: a server-paged table (sorting on the server's sort
// fields; page / size / sort in the URL), a title search, a drawer to write
// a note and one to read or remove it. A notes.created event reloads the page.
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { z } from 'zod'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiDrawer, UiForm, UiInput, UiTextarea, UiKeyValueTable, useConfirm, useListQuery, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { describe, type Note } from '@/api/client'
import { NOTE_LIST, useNotes } from '@/stores/notes'
import { onEvent } from '@/stores/live'

const store = useNotes()
const confirm = useConfirm()
const lq = useListQuery('notes', NOTE_LIST)
const search = ref('')
const editing = ref(false)
const selected = ref<Note | null>(null)
const error = ref('')

async function load(): Promise<void> {
  const res = await store.list(lq.query.value, search.value)
  if (res?.page) lq.clampTo(res.page) // a page beyond the end answers the last page
}
watch(lq.query, () => void load())
watch(search, () => (lq.page.value !== 1 ? lq.resetPage() : void load()))

let off: (() => void) | null = null
onMounted(() => {
  void load()
  off = onEvent('notes.created', () => void load())
})
onUnmounted(() => off?.())

const when = (s: string) => new Date(s).toLocaleString()
const columns: Column<Note>[] = [
  { key: 'title', label: 'Title', sortable: true },
  { key: 'author_id', label: 'Author', hideOnStack: true },
  { key: 'created_at', label: 'Written', format: (n) => when(n.created_at), sortable: true, defaultDir: 'desc' },
]

const noteSchema = z.object({
  title: z.string().trim().min(1, 'Required').max(200),
  body: z.string().max(10000).default(''),
})
const form = useZodForm(noteSchema, {
  onSubmit: (v) => store.create(v.title, v.body),
  onSuccess: () => {
    editing.value = false
    void load()
  },
})
function startNew(): void {
  form.reset({ title: '', body: '' })
  editing.value = true
}

async function remove(): Promise<void> {
  const n = selected.value
  if (!n || !(await confirm.ask({ title: 'Remove this note?', text: n.title, confirmLabel: 'Remove', danger: true }))) return
  try {
    await store.remove(n.id)
    selected.value = null
    void load()
  } catch (e) {
    error.value = describe(e)
  }
}
</script>

<template>
  <UiPage title="Notes">
    <template #actions><UiButton icon="mdi-plus" data-test="note-new" @click="startNew">New note</UiButton></template>
    <template #filters>
      <div class="md:max-w-sm"><UiInput id="notes-search" v-model="search" label="Search" size="sm" /></div>
    </template>
    <UiAlert v-if="store.error" kind="error" class="mb-3">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" :total="store.total" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" caption="Notes" empty-title="No notes yet" clickable data-test="notes-table" @row-click="(n: Note) => { selected = n; error = '' }" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort" />
    </UiCard>
    <UiDrawer v-model="editing" title="New note" size="lg">
      <UiForm :form="form">
        <div class="flex flex-col gap-4">
          <UiInput v-bind="form.field('title')" label="Title" required data-test="note-title" />
          <UiTextarea v-bind="form.field('body')" label="Text" :rows="8" />
        </div>
      </UiForm>
      <template #actions><UiButton :loading="form.submitting.value" data-test="note-save" @click="form.submit()">Save</UiButton></template>
    </UiDrawer>
    <UiDrawer :model-value="selected !== null" :title="selected?.title ?? ''" size="lg" @update:model-value="(v: boolean) => { if (!v) selected = null }">
      <template v-if="selected">
        <UiAlert v-if="error" kind="error" class="mb-3">{{ error }}</UiAlert>
        <p class="mb-3 whitespace-pre-wrap">{{ selected.body }}</p>
        <UiKeyValueTable :items="[{ label: 'Author', value: selected.author_id }, { label: 'Written', value: when(selected.created_at) }]" />
      </template>
      <template #actions><UiButton size="sm" variant="soft" color="error" icon="mdi-delete-outline" data-test="note-remove" @click="remove">Remove</UiButton></template>
    </UiDrawer>
  </UiPage>
</template>
