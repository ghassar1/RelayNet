using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Tun.Windows
{
    /// <summary>   
    /// Windows OS implementation of ITunPlatform. 
    /// Responsibility: 
    /// - Create/Open WintuneDevice. 
    /// - Configure IP/DNS/routes on the adapter (Windoes networking configuration)
    /// </summary>
    public sealed class WindowsTunPlatform : ITunPlatform
    {
        public Task<ITunDevice> CreateOrOpenAsync(TunConfig config, CancellationToken ct)
        {
            //Create the device wrapper. WintunDevice.StartAsync will do actual native open/start. 
            ITunDevice dev = new WintunDevice(config); 
            return Task.FromResult(dev);
        }
        public Task ConfigureAsync(ITunDevice device, TunConfig config, CancellationToken ct)
        {
            // TODO: Implement: 
            // - assign adapter IP (AddressCidr)
            // - set DNS (optional)
            // - add routes based on FullTunnel + IncludedRoutes/ExcludedRoutes

            //This is OS config, not packet I/O.
            return Task.CompletedTask;
        }
    }
}
