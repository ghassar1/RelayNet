using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace RelayNet.Tun.Windows
{
    [SupportedOSPlatform("windows")]
    internal sealed class WfpPolicyManager
    {
        private readonly TunConfig _config;
        private WfpPolicyState _state = WfpPolicyState.NotApplied;

        public WfpPolicyManager(TunConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public WfpPolicyState State => _state;

        public Task ApplyAsync(WfpBootstrapContext context, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on Windows only.");
            ArgumentNullException.ThrowIfNull(context);

            if (!context.IsControlPlaneReady)
                throw new InvalidOperationException("Control-plane handshake is not ready; refusing to enforce WFP egress policy.");

            // Phase 3 scaffold:
            // - Open WFP engine
            // - Add provider/sublayer
            // - Add bootstrap allow filters (relay/control-plane)
            // - Add Wintun-only egress allow filters
            // - Add block-all-other-outbound filters
            // - Commit transaction
            _state = WfpPolicyState.Applied;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on Windows only.");

            if (_state == WfpPolicyState.NotApplied)
                return Task.CompletedTask;

            // Phase 3 scaffold:
            // - Open WFP engine
            // - Remove filters by known IDs/provider/sublayer
            // - Commit transaction
            _state = WfpPolicyState.NotApplied;
            return Task.CompletedTask;
        }

        public Task CleanupStaleArtifactsAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on Windows only.");

            // Phase 3 scaffold:
            // - Remove stale filters/sublayer/provider from prior crashed sessions.
            return Task.CompletedTask;
        }
    }

    internal enum WfpPolicyState
    {
        NotApplied = 0,
        Applied = 1,
    }

    internal sealed class WfpBootstrapContext
    {
        public bool IsControlPlaneReady { get; init; }
        public string[] RelayEndpointIps { get; init; } = Array.Empty<string>();
    }
}
