// Shared singletons must match the platform shell
// (go-tangra specs/003-application-gateway/contracts/federation.md).
// A production remote never carries fallback copies of the singletons: the
// shell always provides them (import: false), which keeps the module bundle
// to its own code. `vite` dev keeps the local copies for standalone use.
const hostOnly = process.env.NODE_ENV === 'production' ? { import: false as const } : {}
export const shared = {
  vue: { singleton: true, requiredVersion: '^3.5.0', ...hostOnly },
  'vue-router': { singleton: true, requiredVersion: '^5.0.0', ...hostOnly },
  pinia: { singleton: true, requiredVersion: '^4.0.0', ...hostOnly },
  '@casl/ability': { singleton: true, requiredVersion: '^7.0.0', ...hostOnly },
  '@casl/vue': { singleton: true, requiredVersion: '^3.0.0', ...hostOnly },
  zod: { singleton: true, requiredVersion: '^4.0.0', strictVersion: true, ...hostOnly },
  '@go-tangra/ui': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true, ...hostOnly },
  '@go-tangra/ui/forms': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true, ...hostOnly },
  '@go-tangra/ui/api': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true, ...hostOnly },
}

// name = the module; exposes = the manifest's Exposes (src/manifest.rs).
export const remoteConfig = {
  name: 'notes',
  filename: 'remoteEntry.js',
  manifest: true,
  exposes: {
    './routes': './src/remote/routes.ts',
    './nav': './src/remote/nav.ts',
    './boot': './src/remote/boot.ts',
  },
  shared,
  // The shell loads remotes at runtime; no consumer imports generated types.
  dts: false,
}
