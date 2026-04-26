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
        public uint SessionCapacityBytes { get; init; } = 0x400000;

        public required string AdapterName { get; init; }

        public required string AddressCidrV4 { get; init; }   // example: 10.10.0.2/24
        public required string GatewayV4 { get; init; }       // example: 10.10.0.1

        public required string AddressCidrV6 { get; init; }   // example: fd00::2/64
        public required string GatewayV6 { get; init; }       // example: fd00::1

        public string[]? DnsServers { get; init; }

        public string TunnelType { get; init; } = "RelayNet";

    }
}
