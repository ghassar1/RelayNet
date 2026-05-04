using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace RelayNet.Tun.Windows.Native
{
    internal class IpHlpApi
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
        private static extern int AddIPAddress(uint Address, uint IpMask, int IfIndex, out uint NteContext, out uint Ntenstance);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIPAddress(uint NteContext);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestRoute(uint dwDestAddr, uint dwSourceAddr, out MIB_IPFORWARDROW pBestRoute);

        [StructLayout(LayoutKind.Sequential)]
        internal struct SOCKADDR_INET {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
            public Byte[] Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIB_IPFORWARD_ROW2
        {
            public ulong InterfaceLuid;
            public uint InterfaceIndex;
            public SOCKADDR_INET DestinationPrefixPrefix;
            public byte DestinationPrefixLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Pad1;
            public SOCKADDR_INET NextHop;
            public byte SitePrefixLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]


            public byte[] Pad2;
            public uint ValidLifetime;
            public uint PreferredLifeTime;
            public uint Metric;
            public uint Protocol;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Loopback;
            [MarshalAs(UnmanagedType.Bool)]
            public bool AutoconfigureAddress;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Publish;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Immortal;
            public uint Age;
            public uint Origin;


        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int CreateIpForwardEntry2(ref MIB_IPFORWARD_ROW2 row);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestRoute2(
            IntPtr interfaceLuid,
            uint interfaceIndex,
            IntPtr sourceAddress,
            ref SOCKADDR_INET destinationAddress,
            uint addressSortOptions,
            out MIB_IPFORWARD_ROW2 bestRoute,
            IntPtr bestSourceAddress);

        internal static void AddOrUpdateDefaultRouteIpv4(int interfaceIndex, IPAddress nextHop, int metric)
        {

            if (nextHop.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Gateway must be Ipv4 .", nameof(nextHop));

            var row = new MIB_IPFORWARDROW
            {
                dwForwardDest = ToNetworkOrderUnit32(IPAddress.Any),
                dwForwardMask = ToNetworkOrderUnit32(IPAddress.Any),
                dwForwardPolicy = 0,
                dwForwardNextHop = ToNetworkOrderUnit32(nextHop),
                dwForwardIfIndex = (uint)interfaceIndex,
                dwForwardType = 4,
                dwForwardProto = 3,
                dwForwardAge = 0,
                dwForwardNextHopAS = 0,
                dwForwardMetric1 = checked((uint)Math.Max(metric, 1)), 
                dwForwardMetric2 = uint.MaxValue,
                dwForwardMetric3 = uint.MaxValue,
                dwForwardMetric4 = uint.MaxValue,
                dwForwardMetric5 = uint.MaxValue
            };

            int createErr = CreateIpForwardEntry(ref row);
            if(createErr == 0)
                return;

            if (createErr == ERROR_OBJECT_ALREADY_EXISTS)
            { 
                int setErr = SetIpForwardEntry(ref row);
                if(setErr == 0)
                    return;

                throw new Win32Exception(setErr, $"SetIpForwardEntry failed for interface {interfaceIndex}.");
            }
            throw new Win32Exception(createErr, $"CreateIpForwardEntry failed for interface {interfaceIndex}.");
        }

        internal static void AddOrUpdateDefaultRouteIpv6(int interfaceIndex, IPAddress nextHop, int metric)
        {
            if (nextHop.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new ArgumentException("Gateway must be IPv6", nameof(nextHop));

            var row = new MIB_IPFORWARD_ROW2
            {
                InterfaceLuid = 0,
                InterfaceIndex = (uint)interfaceIndex,
                DestinationPrefixPrefix = new SOCKADDR_INET { Data = new byte[28] },
                DestinationPrefixLength = 0,
                Pad1 = new byte[3],
                NextHop = new SOCKADDR_INET { Data = new byte[28] },
                SitePrefixLength = 0,
                Pad2 = new byte[3],
                ValidLifetime = uint.MaxValue,
                PreferredLifeTime = uint.MaxValue,
                Metric = checked((uint)Math.Max(metric, 1)),
                Protocol = 3
            };
            
            byte[] b = nextHop.GetAddressBytes();
            Array.Copy(b, 0, row.NextHop.Data, 8, 16);
            row.NextHop.Data[0] = 23; // AF INET6

            int err = CreateIpForwardEntry2(ref row);
            if (err != 0 && err != ERROR_OBJECT_ALREADY_EXISTS && err != 183)
                throw new Win32Exception(err,$"CreateIpForwardEntry2 failed interface {interfaceIndex}.");

        }

        internal static uint? AddOrUpdateIPv4Address(int interfaceIndex, IPAddress address, IPAddress mask)
        {
           if(address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Address must be IPv4.", nameof(address));
            if(mask.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Mask must be IPv4.", nameof(mask));

            int err = AddIPAddress(ToNetworkOrderUnit32(address), ToNetworkOrderUnit32(mask), interfaceIndex, out uint nteContext, out _);

            // 5010/183 can show up when address already exists. 
            if(err == 0 || err == ERROR_OBJECT_ALREADY_EXISTS || err == 183)
                return err == 0 ? nteContext : null;

            throw new Win32Exception(err, $"AddIpAddress failed for interface {interfaceIndex} for {address}/{mask}.");
        }
        internal static void DeleteIPv4Address(uint nteContext)
        { 
            int err = DeleteIPAddress(nteContext);
            if(err != 0)
                throw new Win32Exception(err, $"DeleteIPAddress failed for NTE context {nteContext}.");
        }
        internal static int GetBestInterfaceForDestinationIp4(IPAddress destination)
        { 
            if (destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Destination must be IPv4", nameof(destination));

            int err = GetBestRoute(ToNetworkOrderUnit32(destination), ToNetworkOrderUnit32(IPAddress.Any), out var bestRoute);

            if (err != 0)
                throw new Win32Exception(err, $"GetBestRoute failed for destination {destination}.");

            return checked((int)bestRoute.dwForwardIfIndex);
        }
        internal static int GetBestInterfaceForDestinationIpV6(IPAddress destination)
        {
            if (destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new ArgumentException("Destination must be IPv6", nameof(destination));

            var sockaddr = CreateSockAddrInetV6(destination);

            int err = GetBestRoute2(IntPtr.Zero, 0, IntPtr.Zero, ref sockaddr, 0, out var bestRoute, IntPtr.Zero);

            if (err != 0)
                throw new Win32Exception(err, $"GetBestRoute2 failed for destination {destination}.");

            return checked((int)bestRoute.InterfaceIndex);

        }
        private static SOCKADDR_INET CreateSockAddrInetV6(IPAddress address)
        {
            var sockAddr = new SOCKADDR_INET { Data = new byte[28] };
                sockAddr.Data[0] = 23; //AF_INET6
            byte[] bytes = address.GetAddressBytes();
            Array.Copy(bytes, 0, sockAddr.Data, 8, 16);
            return sockAddr;
        }
        private static uint ToNetworkOrderUnit32(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            if(bytes.Length !=4)
                throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));

            return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        }
    }
}
