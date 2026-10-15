// notes.created reaches the UI over the platform's realtime bus: the module
// publishes it to the tenant's Valkey stream and the gateway relays the
// stream to the browser. Inside the shell the module listens through the
// shell's shared connection (BootContext.live, handed to ./boot); standalone
// it opens its own EventSource on the gateway's stream.

/** The shell's shared realtime bus (BootContext.live). */
export interface PlatformBus {
  on(type: string, fn: (data: unknown) => void): () => void
}

/** The gateway's platform event stream. */
export const PLATFORM_STREAM = '/gateway/v1/stream'

let platformBus: PlatformBus | null = null

/** Hands the shell's bus to the module (called by ./boot). */
export function setPlatformBus(bus: PlatformBus | null | undefined): void {
  platformBus = bus ?? null
}

/** Calls fn for every event of type; returns the unsubscribe function. */
export function onEvent(type: string, fn: (data: unknown) => void): () => void {
  if (platformBus) return platformBus.on(type, fn)
  const source = new EventSource(PLATFORM_STREAM, { withCredentials: true })
  source.addEventListener(type, (e) => {
    try {
      fn(JSON.parse((e as MessageEvent).data))
    } catch {
      /* non-JSON payloads are ignored */
    }
  })
  return () => source.close()
}
