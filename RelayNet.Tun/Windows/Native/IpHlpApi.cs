using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace RelayNet.Tun.Windows.Native
{
    internal static class IpHlpApi
    {
        private const int ERROR_OBJECT_ALREADY_EXISTS = 5010;

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest;
            public uint dwForwardMask;
            public uint dwForwardPolicy;
            public uint dwForwardNextHop;
            public uint dwForwardIfIndex;
            public uint dwForwardType;
            public uint dwForwardProto;
            public uint dwForwardAge;
            public uint dwForwardNextHopAS;
            public uint dwForwardMetric1;
            public uint dwForwardMetric2;
            public uint dwForwardMetric3;
            public uint dwForwardMetric4;
            public uint dwForwardMetric5;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int CreateIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int SetIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int AddIPAddress(
            uint Address,
            uint IpMask,
            int IfIndex,
            out uint NteContext,
            out uint NteInstance);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIPAddress(uint NteContext);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestRoute(
            uint dwDestAddr,
            uint dwSourceAddr,
            out MIB_IPFORWARDROW pBestRoute);

        internal static void AddOrUpdateDefaultRouteIPv4(int interfaceIndex, IPAddress nextHop, int metric)
        {
            if (nextHop.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Gateway must be IPv4.", nameof(nextHop));

            var row = new MIB_IPFORWARDROW
            {
                dwForwardDest = ToNetworkOrderUInt32(IPAddress.Any),
                dwForwardMask = ToNetworkOrderUInt32(IPAddress.Any),
                dwForwardPolicy = 0,
                dwForwardNextHop = ToNetworkOrderUInt32(nextHop),
                dwForwardIfIndex = checked((uint)interfaceIndex),
                dwForwardType = 4, // MIB_IPROUTE_TYPE_INDIRECT
                dwForwardProto = 3, // MIB_IPPROTO_NETMGMT
                dwForwardAge = 0,
                dwForwardNextHopAS = 0,
                dwForwardMetric1 = checked((uint)Math.Max(metric, 1)),
                dwForwardMetric2 = uint.MaxValue,
                dwForwardMetric3 = uint.MaxValue,
                dwForwardMetric4 = uint.MaxValue,
                dwForwardMetric5 = uint.MaxValue,
            };

            int createErr = CreateIpForwardEntry(ref row);
            if (createErr == 0)
                return;

            if (createErr == ERROR_OBJECT_ALREADY_EXISTS)
            {
                int setErr = SetIpForwardEntry(ref row);
                if (setErr == 0)
                    return;

                throw new Win32Exception(setErr, $"SetIpForwardEntry failed for interface {interfaceIndex}.");
            }

            throw new Win32Exception(createErr, $"CreateIpForwardEntry failed for interface {interfaceIndex}.");
        }

        internal static uint? AddOrUpdateIPv4Address(int interfaceIndex, IPAddress address, IPAddress mask)
        {
            if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Address must be IPv4.", nameof(address));
            if (mask.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Mask must be IPv4.", nameof(mask));

            int err = AddIPAddress(
                ToNetworkOrderUInt32(address),
                ToNetworkOrderUInt32(mask),
                interfaceIndex,
                out uint nteContext,
                out _);

            // 5010/183 can show up when address already exists.
            if (err == 0 || err == ERROR_OBJECT_ALREADY_EXISTS || err == 183)
                return err == 0 ? nteContext : null;

            throw new Win32Exception(err, $"AddIPAddress failed on interface {interfaceIndex} for {address}/{mask}.");
        }

        internal static void DeleteIPv4Address(uint nteContext)
        {
            int err = DeleteIPAddress(nteContext);
            if (err != 0)
                throw new Win32Exception(err, $"DeleteIPAddress failed for NTE context {nteContext}.");
        }

        internal static int GetBestInterfaceForDestinationIPv4(IPAddress destination)
        {
            if (destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Destination must be IPv4.", nameof(destination));

            int err = GetBestRoute(
                ToNetworkOrderUInt32(destination),
                ToNetworkOrderUInt32(IPAddress.Any),
                out MIB_IPFORWARDROW bestRoute);

            if (err != 0)
                throw new Win32Exception(err, $"GetBestRoute failed for destination {destination}.");

            return checked((int)bestRoute.dwForwardIfIndex);
        }

        private static uint ToNetworkOrderUInt32(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length != 4)
                throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));

            return ((uint)bytes[0] << 24) |
                   ((uint)bytes[1] << 16) |
                   ((uint)bytes[2] << 8) |
                    bytes[3];
        }
    }
}
