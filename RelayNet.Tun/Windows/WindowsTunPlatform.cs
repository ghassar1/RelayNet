using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Tun.Windows
{
    /// <summary>   
    /// Windows implemntation of <see cref="ITunPlatform"/>.
    /// Platform owns OS-level network policy/configuration (IP,routes, DNS).
    /// Device owns packet I/O only.
    /// </summary>
    public sealed class WindowsTunPlatform : ITunPlatform
    {
        public Task<ITunDevice> CreateOrOpenAsync(TunConfig config, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(config);
            ct.ThrowIfCancellationRequested();

            ITunDevice device = new WintunDevice(config);
            return Task.FromResult(device);

        }
        public Task ConfigureAsync(ITunDevice device, TunConfig config, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(config);
            ct.ThrowIfCancellationRequested();

            var manager = new WindowsNetworkPolicyManager(config);
            return manager.ConfigureAdapterAndRoutesAsync(ct);
        }

        public async Task EnableKillSwitchAsync(TunConfig config, WfpBootsrapContext bootsrapContext, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentNullException.ThrowIfNull(bootsrapContext);
            ct.ThrowIfCancellationRequested();

            var wfp = new WfpPolicyManager(config);
            await wfp.CleanupStaleArtifactsAsync(ct);
            await wfp.ApplyAsync(bootsrapContext, ct);
        }
    }
}
