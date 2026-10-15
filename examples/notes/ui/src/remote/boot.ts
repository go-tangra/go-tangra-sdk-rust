import { setPlatformBus, type PlatformBus } from '@/stores/live'

// The shell calls ./boot once the module is mounted (contracts/federation.md)
// with its BootContext; notes keeps the shared realtime bus so notes.created
// rides the shell's single platform stream.
export default function boot(ctx: { live?: PlatformBus }): void {
  setPlatformBus(ctx.live)
}
