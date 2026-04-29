using RelayNet.Tun.Windows.Native;
using Microsoft.Win32;
using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace RelayNet.Tun.Windows
{
    [SupportedOSPlatform("windows")]
    internal sealed class WindowsNetworkPolicyManager
    {
        private readonly TunConfig _config;
        private const string TcpipV4Path = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        private const string TcpipV6Path = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

        public WindowsNetworkPolicyManager(TunConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public Task ConfigureAdapterAndRoutesAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WindowsNetworkPolicyManager is supported on Windows only.");

            ValidateDualStackInputs();

            var (ipv4, prefix4) = ParseCidr(_config.AddressCidrV4);
            var adapter = GetAdapterByName(_config.AdapterName);
            int interfaceIndex = GetInterfaceIndex(adapter);
            var rollbackState = new RollbackState();

            try
            {
                rollbackState.Ipv4AddressContext = ApplyIpv4Address(interfaceIndex, ipv4, prefix4);
                ConfigureDns(adapter, ct, rollbackState);

                var gateway4 = IPAddress.Parse(_config.GatewayV4);

                IpHlpApi.AddOrUpdateDefaultRouteIPv4(interfaceIndex, gateway4, metric: 3);
                VerifyDefaultRouteOwner(interfaceIndex);
                return Task.CompletedTask;
            }
            catch
            {
                RollbackBestEffort(adapter.Id, rollbackState);
                throw;
            }
        }

        private static void VerifyDefaultRouteOwner(int expectedInterfaceIndex)
        {
            // Verify the actual selected route for internet test destinations, not just route presence.
            int best1 = IpHlpApi.GetBestInterfaceForDestinationIPv4(IPAddress.Parse("1.1.1.1"));
            int best2 = IpHlpApi.GetBestInterfaceForDestinationIPv4(IPAddress.Parse("8.8.8.8"));

            if (best1 != expectedInterfaceIndex || best2 != expectedInterfaceIndex)
            {
                throw new InvalidOperationException(
                    $"Default route verification failed. Expected ifIndex={expectedInterfaceIndex}, got best route ifIndex values {best1} and {best2}.");
            }
        }

        private static uint? ApplyIpv4Address(int interfaceIndex, string ip, int prefixLength)
        {
            var address = IPAddress.Parse(ip);
            var mask = IPAddress.Parse(PrefixToMask(prefixLength));

            return IpHlpApi.AddOrUpdateIPv4Address(interfaceIndex, address, mask);
        }

        private void ConfigureDns(NetworkInterface adapter, CancellationToken ct, RollbackState rollbackState)
        {
            ct.ThrowIfCancellationRequested();
            if (_config.DnsServers is null || _config.DnsServers.Length == 0)
                return;

            rollbackState.OldDnsV4 = GetRegistryDnsValue(TcpipV4Path, adapter.Id);
            rollbackState.OldDnsV6 = GetRegistryDnsValue(TcpipV6Path, adapter.Id);

            string dns = string.Join(",", _config.DnsServers);
            string adapterId = adapter.Id;

            SetRegistryDnsValue(TcpipV4Path, adapterId, dns);
            SetRegistryDnsValue(TcpipV6Path, adapterId, dns);
        }

        private static NetworkInterface GetAdapterByName(string adapterName)
        {
            var match = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(i => string.Equals(i.Name, adapterName, StringComparison.OrdinalIgnoreCase));

            return match ?? throw new InvalidOperationException($"Could not find adapter '{adapterName}'.");
        }

        private static int GetInterfaceIndex(NetworkInterface adapter)
        {
            int? index = adapter.GetIPProperties()?.GetIPv4Properties()?.Index;
            if (!index.HasValue)
                throw new InvalidOperationException($"Could not resolve IPv4 interface index for adapter '{adapter.Name}'.");
            return index.Value;
        }

        private static (string Ip, int PrefixLength) ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new InvalidOperationException($"Invalid CIDR: {cidr}");

            return (parts[0], int.Parse(parts[1]));
        }

        private static string PrefixToMask(int prefix)
        {
            if (prefix is < 0 or > 32)
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
                throw new InvalidOperationException($"Could not open registry key for adapter '{adapterId}' at '{rootPath}'.");

            key.SetValue("NameServer", dnsServersCsv, RegistryValueKind.String);
        }

        private static string? GetRegistryDnsValue(string rootPath, string adapterId)
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{rootPath}\{adapterId}", writable: false);
            if (key is null)
                return null;

            return key.GetValue("NameServer") as string;
        }

        private static void RollbackBestEffort(string adapterId, RollbackState state)
        {
            try
            {
                if (state.OldDnsV4 is not null)
                    SetRegistryDnsValue(TcpipV4Path, adapterId, state.OldDnsV4);
            }
            catch { }

            try
            {
                if (state.OldDnsV6 is not null)
                    SetRegistryDnsValue(TcpipV6Path, adapterId, state.OldDnsV6);
            }
            catch { }

            try
            {
                if (state.Ipv4AddressContext.HasValue)
                    IpHlpApi.DeleteIPv4Address(state.Ipv4AddressContext.Value);
            }
            catch { }
        }

        private void ValidateDualStackInputs()
        {
            _ = ParseCidr(_config.AddressCidrV4);
            _ = ParseCidr(_config.AddressCidrV6);

            if (!IPAddress.TryParse(_config.GatewayV4, out IPAddress? g4) ||
                g4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new InvalidOperationException($"Invalid IPv4 gateway: {_config.GatewayV4}");

            if (!IPAddress.TryParse(_config.GatewayV6, out IPAddress? g6) ||
                g6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new InvalidOperationException($"Invalid IPv6 gateway: {_config.GatewayV6}");
        }

        private sealed class RollbackState
        {
            public string? OldDnsV4 { get; set; }
            public string? OldDnsV6 { get; set; }
            public uint? Ipv4AddressContext { get; set; }
        }

    }
}
