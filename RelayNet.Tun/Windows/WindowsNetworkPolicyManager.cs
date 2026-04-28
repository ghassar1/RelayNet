using Microsoft.Win32;
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
            var adapter = GetAdapterByName(_config.AdapterName);
            int interfaceIndex = GetInterfaceIndex(adapter);

            ApplyIpv4Address(interfaceIndex, ipv4, prefix4);
            ConfigureDnsAsync(adapter,ct); 

            var gateway4 = IPAddress.Parse(_config.GatewayV4);

            IpHlpApi.AddOrUpdateDefaultRouteIpv4(interfaceIndex, gateway4, metric: 3);
            VerifyDefaultRouteOwner(interfaceIndex);
            return Task.CompletedTask;
        }

        private static void VerifyDefaultRouteOwner(int expectedInterfaceIndex)
        {
            // Verify the actual selected route for internet test destinations, not jus route presence.

            int best1 = IpHlpApi.GetBestInterfaceForDestinationIp4(IPAddress.Parse("1.1.1.1"));
            int best2 = IpHlpApi.GetBestInterfaceForDestinationIp4(IPAddress.Parse("8.8.8.8"));

            if (best1 != expectedInterfaceIndex || best2 != expectedInterfaceIndex)
            {
                throw new InvalidOperationException($"Default route verification failed. Expected ifIndex={expectedInterfaceIndex}," +
                    $" got best route ifIndex value {best1} and {best2}.");
            }
        }

        private static void ApplyIpv4Address(int interfaceIndex, string ip, int prefixLength)
        {
            var address = IPAddress.Parse(ip);
            var mask = IPAddress.Parse(PrefixToMask(prefixLength));
            IpHlpApi.AddOrUpdateIPv4Address(interfaceIndex, address, mask);
        }

        private static void ConfigureDnsAsync(NetworkInterface adapter, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (_config.DnsServers is null || _config.DnsServers.Length == 0)
                return;
            string dns = string.Join(",", _config.DnsServers);
            string adapterId = adapter.Id;

            const string tcpipV4Path = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            const string tcpipV6Path = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

            SetRegistryDnsValue(tcpipV4Path, adapterId, dns); 
            SetRegistryDnsValue(tcpipV6Path, adapterId, dns);


        }

        private static NetworkInterface GetAdapterByName(string adapterName)
        {
            var match = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(i => string.Equals(i.Name, adapterName, StringComparison.OrdinalIgnoreCase));
            return match ?? throw new InvalidOperationException($"Could not find adapter '{adapterName}'.");
        }
        private static int GetInterfaceIndex(NetworkInterface adater)
        { 
            int? index = adater.GetIPProperties().GetIPv4Properties()?.Index;
            if (!index.HasValue)
                throw new InvalidOperationException($"Could not resolve IPv4 interface index for adapter '{adater.Name}'.");
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
        private static void SetRegistryDnsValue(string rootPath, string adapterId, string dnsServersCsv)
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{rootPath}\{adapterId}", writable: true);
         
            if (key is null)
                throw new InvalidOperationException($"Could not open registry key for adapter '{adapterId}' at  '{rootPath}'.");

            key.SetValue("NameServer", dnsServersCsv, RegistryValueKind.String);
        }
    }
}
