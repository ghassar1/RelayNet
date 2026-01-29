using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Tun
{
    /// <summary>
    /// Coinfiguration for the virtual tunnel interface. 
    /// This is pure data: adapter name, IP, DNS, routes, and mode.
    /// </summary>
    public sealed class TunConfig
    {
       // Friendly name for the adapter (e.g., "RelayNet"). 
       public required string AdapterName { get; init; }

        /// <summary>
        /// IP address with CIDR 
        /// This will be assigned to the TUN adapter.
        /// </summary>
        /// 
        public required string AddressCidr { get; init; }

        /// <summary>
        ///     Optional DNS servers to use while tunnel is active (e.g., ["1.1.1.1", "8.8.8.8"]).
        /// </summary>
        /// 
        public string[]? DnsServers { get; init; }

        /// <summary>
        /// For split tunnel: routes to send via tunnel (CIDR strings). 
        /// Example ["10.10.0.0/16", "172.16.0.0/12"]. 
        /// 
        public string[]? IncludedRourtes { get; init; }

        /// <summary>
        /// For full tunnel: routes that must not go through the tunnel (control-plane exclusions).
        /// Example: Entry relay IP, Directory IP. 
        /// 
        public string[]? ExcludedRoutes { get; init; }
    }
}
