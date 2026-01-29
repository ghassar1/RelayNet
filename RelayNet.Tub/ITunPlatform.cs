using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Tun
{
    /// <summary>
    /// OS-sepecifi operations. 
    /// Responsibility: 
    /// - Create/Open adaptor
    /// - Configure IP/DNS/routes
    /// - Return an ITunDevice for packet I/O
    /// </summary>
    public interface ITunPlatform
    {
        Task<ITunDevice> CreateOrOpenAsync(TunConfig config, CancellationToken ct); 

        Task ConfigureAsync(TunConfig config, CancellationToken ct);
    }
}
