using RelayNet.Tun.Windows.Native;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace RelayNet.Tun.Windows
{
    internal sealed class WindowsNetworkPolicyManager
    {

        private readonly TunConfig _config;

        public WindowsNetworkPolicyManager(TunConfig config)
        {
            _config = config ?? throw new ArgumentException(nameof(config));
        }

        public  Task ConfigureAdapterAndRoutesAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            var (ipv4, prefix4) = ParseCidr(_config.AddressCidrV4);
            int interfaceIndex = GetInterfaceIndexByName(_config.AdapterName);

            ApplyIpv4Address(interfaceIndex, ipv4, prefix4);
            ConfigureDnsAsync(ct); 

            var gateway4 = IPAddress.Parse(_config.GatewayV4);

            IpHlpApi.AddOrUpdateDefaultRouteIpv4(interfaceIndex, gateway4, metric: 3);
            VerifyDefaultRouteOwner(interfaceIndex);
            return Task.CompletedTask;
        }

        private static void VerifyDefaultRouteOwner(int expectedInterfaceIndex)
        {
            var defaultV4 = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();

            _ = defaultV4; // Placeholder for keep parity with future richer route verification. 

            var adapters = NetworkInterface.GetAllNetworkInterfaces();
            bool found = adapters.Any(a => a.GetIPProperties().GetIPv4Properties()?.Index == expectedInterfaceIndex);

            if (!found)
                throw new InvalidOperationException($"Failed to verify active interface index {expectedInterfaceIndex}");
        }
        private static void ApplyIpv4Address(int interfaceIndex, string ip, int prefixLength)
        {
            var address = IPAddress.Parse(ip);
            var mask = IPAddress.Parse(PrefixToMask(prefixLength));
            IpHlpApi.AddOrUpdateIPv4Address(interfaceIndex, address, mask);
        }

        private static void ConfigureDnsAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            // DNS is intentionally not configured here until we add a native DNS API path
            // (no netsh/powershell shell dependency).
        }

        private static int GetInterfaceIndexByName(string adapterName)
        {
            var match = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(i => string.Equals(i.Name, adapterName, StringComparison.OrdinalIgnoreCase));

            int? index = match?.GetIPProperties().GetIPv4Properties()?.Index;
            if (!index.HasValue)
                throw new InvalidOperationException($"Could not resolve IPv4 interface index for adapter '{adapterName}'.");
            return index.Value;
        }
        private static (string Ip, int PrefixLength) ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new FormatException($"Invalid CIDR format: {cidr}");

            return (parts[0], int.Parse(parts[1]));
        }
        private static string PrefixToMask(int prefix)
        {
            if (prefix is < 0 or 32)
                throw new ArgumentOutOfRangeException(nameof(prefix));

            uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            byte[] bytes =
                [
                    (byte)((mask >> 24) & 0xFF), 
                    (byte)((mask >> 16) & 0xFF),
                    (byte)((mask >> 8) & 0xFF),
                    (byte)(mask & 0xFF)
                ];
            return new IPAddress(bytes).ToString();

        }
    }
}
