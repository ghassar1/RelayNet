using Microsoft.Win32;
using RelayNet.Tun.Windows.Native;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Text;
using static RelayNet.Tun.Windows.Native.IpHlpApi;

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
            _config = config ?? throw new ArgumentException(nameof(config));
        }

        public Task ConfigureAdapterAndRoutesAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WindowsNetworkPolicyManager is suppported on windows only.");

            ValidateDualStackInputs();

            var (ipv4, prefix4) = ParseCidr(_config.AddressCidrV4);
            var adapter = GetAdapterByName(_config.AdapterName);
            int interfaceIndex = GetInterfaceIndex(adapter);
            var rollbackstate = new RollbackState();


            try
            {
                rollbackstate.Ipv4AddressContext = ApplyIpv4Address(interfaceIndex, ipv4, prefix4);
                ConfigureDns(adapter, ct, rollbackstate);

                var gateway4 = IPAddress.Parse(_config.GatewayV4);

                var gateway6 = IPAddress.Parse(_config.GatewayV6);

                IpHlpApi.AddOrUpdateDefaultRouteIpv4(interfaceIndex, gateway4, metric: 3);
                rollbackstate.AppliedGatewayV4 = gateway4;
                bool ipv6RouteApplied = TryAddIpv6DefaultRoute(interfaceIndex, gateway6);
                if (ipv6RouteApplied)
                    rollbackstate.AppliedGatewayV6 = gateway6;
                rollbackstate.InterfaceIndex = interfaceIndex;
                VerifyDefaultRouteOwner(interfaceIndex, verifyIpv6: ipv6RouteApplied);
                return Task.CompletedTask;

            }
            catch
            {
                RollbackBestEffort(adapter.Id, rollbackstate);
                throw;
            }

        }

        private static void VerifyDefaultRouteOwner(int expectedInterfaceIndex, bool verifyIpv6)
        {
            // Verify the actual selected route for internet test destinations, not jus route presence.

            int best1;
            int best2;
            try
            {
                best1 = IpHlpApi.GetBestInterfaceForDestinationIp4(IPAddress.Parse("1.1.1.1"));
                best2 = IpHlpApi.GetBestInterfaceForDestinationIp4(IPAddress.Parse("8.8.8.8"));
            }
            catch (Win32Exception)
            {
                return;
            }

            if (best1 != expectedInterfaceIndex || best2 != expectedInterfaceIndex)
            {
                throw new InvalidOperationException($"Default route verification failed. Expected ifIndex={expectedInterfaceIndex}," +
                    $" got best route ifIndex value {best1} and {best2}.");
            }

            if (!verifyIpv6)
                return;

            int bestv6 = IpHlpApi.GetBestInterfaceForDestinationIpV6((IPAddress.Parse("2606:4700:4700::1111")));
            if (bestv6 != expectedInterfaceIndex)
                throw new InvalidOperationException($"IPv6 default route verification failed. Expected ifIndex={expectedInterfaceIndex}, got {bestv6}.");
        }
        private static bool TryAddIpv6DefaultRoute(int interfaceIndex, IPAddress gateway6)
        {
            try
            {
                IpHlpApi.AddOrUpdateDefaultRouteIpv6(interfaceIndex, gateway6, metric: 3);
                return true;
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        private static uint? ApplyIpv4Address(int interfaceIndex, string ip, int prefixLength)
        {
            if (IsIpv4AddressAlreadyConfigured(interfaceIndex, ip))
                return null;
            EnsureIpv4AddressNotUsedByAnotherInterface(interfaceIndex, ip);

            var address = IPAddress.Parse(ip);
            var mask = IPAddress.Parse(PrefixToMask(prefixLength));
            try
            {
                return IpHlpApi.AddOrUpdateIPv4Address(interfaceIndex, address, mask);
            }
            catch (Win32Exception ex)
            {
                // On some Windows builds/drivers AddIPAddress can report failure while the address is already applied.
                if (IsIpv4AddressAlreadyConfigured(interfaceIndex, ip))
                    return null;
                if (ex.NativeErrorCode == 87)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        Thread.Sleep(250);
                        if (IsIpv4AddressAlreadyConfigured(interfaceIndex, ip))
                            return null;
                        try
                        {
                            return IpHlpApi.AddOrUpdateIPv4Address(interfaceIndex, address, mask);
                        }
                        catch (Win32Exception) when (i < 2)
                        {
                        }
                    }
                }

                throw new Win32Exception(ex.NativeErrorCode,
                    $"Failed to assign IPv4 {ip}/{mask} on ifIndex={interfaceIndex}. " +
                    $"Win32={ex.NativeErrorCode}. Ensure the IP is not in use and adapter supports IPv4 assignment.");
            }
        }
        private static bool IsIpv4AddressAlreadyConfigured(int interfaceIndex, string ip)
        {
            var unicast = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => TryGetIpv4InterfaceIndex(n) == interfaceIndex)?
                .GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()) ?? Enumerable.Empty<string>();

            return unicast.Any(a => string.Equals(a, ip, StringComparison.OrdinalIgnoreCase));
        }
        private static void EnsureIpv4AddressNotUsedByAnotherInterface(int interfaceIndex, string ip)
        {
            var owner = NetworkInterface.GetAllNetworkInterfaces()
                .Select(n => new
                {
                    Name = n.Name,
                    Index = TryGetIpv4InterfaceIndex(n),
                    Ips = n.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(a => a.Address.ToString())
                })
                .FirstOrDefault(n => n.Index.HasValue && n.Index.Value != interfaceIndex &&
                                     n.Ips.Any(x => string.Equals(x, ip, StringComparison.OrdinalIgnoreCase)));

            if (owner is not null)
                throw new InvalidOperationException($"IPv4 address conflict: {ip} is already assigned on interface '{owner.Name}' (ifIndex={owner.Index}).");
        }
        private static int? TryGetIpv4InterfaceIndex(NetworkInterface nic)
        {
            try
            {
                return nic.GetIPProperties().GetIPv4Properties()?.Index;
            }
            catch (NetworkInformationException)
            {
                return null;
            }
            catch (NotImplementedException)
            {
                return null;
            }
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
                throw new InvalidOperationException($"Could not open registry key for adapter '{adapterId}' at  '{rootPath}'.");

            key.SetValue("NameServer", dnsServersCsv, RegistryValueKind.String);
        }

        private static string? GetRegistryDnsValue(string rootPath, string adapterId)
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{rootPath}\{adapterId}", writable: false);
            if (key is null)
                return null;
            return key.GetValue("NameServer") as string;
        }
        // why called best efford what could go wrong
        private static void RollbackBestEffort(string adapterId, RollbackState state)
        {
            try
            {
                if (state.OldDnsV4 is not null)
                    SetRegistryDnsValue(TcpipV4Path, adapterId, state.OldDnsV4);
            }
            catch
            {

            }
            try
            {
                if (state.OldDnsV6 is not null)
                    SetRegistryDnsValue(TcpipV6Path, adapterId, state.OldDnsV6);
            }
            catch
            {

            }
            try
            {
                if (state.Ipv4AddressContext.HasValue)
                    IpHlpApi.DeleteIPv4Address(state.Ipv4AddressContext.Value);
                RetryBestEffort(() => IpHlpApi.DeleteIPv4Address(state.Ipv4AddressContext.Value), attempts: 3);
            }
            catch
            {

            }
            try
            {
                if (state.InterfaceIndex.HasValue && state.AppliedGatewayV4 is not null)
                    RetryBestEffort(() => IpHlpApi.RemoveDefaultRouteIpv4(state.InterfaceIndex.Value, state.AppliedGatewayV4), attempts: 3);
            }
            catch
            {
            }
            try
            {
                if (state.InterfaceIndex.HasValue && state.AppliedGatewayV6 is not null)
                    RetryBestEffort(() => IpHlpApi.RemoveDefaultRouteIpv6(state.InterfaceIndex.Value, state.AppliedGatewayV6), attempts: 3);
            }
            catch
            {
            }
        }
        private static void RetryBestEffort(Action action, int attempts)
        {
            for (int i = 0; i < attempts; i++)
            {
                try
                {
                    action();
                    return;
                }
                catch when (i < attempts - 1)
                {
                    Thread.Sleep(250);
                }
            }
        }
        private void ValidateDualStackInputs()
        {
            _ = ParseCidr(_config.AddressCidrV4);
            _ = ParseCidr(_config.AddressCidrV6);

            if (!IPAddress.TryParse(_config.GatewayV4, out IPAddress? g4) ||
                    g4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new FormatException($"Invalid IPv4 gateway: {_config.GatewayV4}");

            if (!IPAddress.TryParse(_config.GatewayV6, out IPAddress? g6) ||
                    g6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new FormatException($"Invalid IPv6 gateway: {_config.GatewayV6}");
        }
        private sealed class RollbackState
        {
            public string? OldDnsV4 { get; set; }
            public string? OldDnsV6 { get; set; }
            public uint? Ipv4AddressContext { get; set; }
            public int? InterfaceIndex { get; set; }
            public IPAddress? AppliedGatewayV4 { get; set; }
            public IPAddress? AppliedGatewayV6 { get; set; }
        }
    }
}
