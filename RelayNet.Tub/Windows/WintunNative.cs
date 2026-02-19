using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace RelayNet.Tun.Windows
{
    /// <summary>
    /// Wintun v0.14.x native API (P/Invoke only). 
    /// Keep this file native-only: DllImport + structs/handles, no business logic.
    /// Low-level P/Invoke declarations for wintun.dll
    /// Responsibility: declare native functions/structs only (no logic).
    ///
    /// </summary>
    internal static class WintunNative
    {
        // Note: 
        // These signatures are placeholders until we align with the exact Wintun API you use.
        // keep this file "native-only": DllImport + structs. 

        private const string DllName = "wintun"; // resolves to wintun.dll via runtimes/<rid>/native/

        // --- Handles ---
        // In wintun.h these are opaque pointers/handles; in c# we represent them as InPtr
        internal readonly struct WintunAdapterHandle { 
            public readonly IntPtr Value;
            public WintunAdapterHandle(IntPtr value) => Value = value;
            public bool IsNull => Value == IntPtr.Zero;
        }

        internal readonly struct  WintunSessionHandle
        {
            public readonly IntPtr Value; 
            public WintunSessionHandle(IntPtr value) => Value = value;
            public bool IsNull => Value == IntPtr.Zero;
        }


        // ---- Adapter management ----

        // WINTUN_ADAPTER_HANDLE WintunCreatedAdapter(const WCHAR* Name, const WCHAR* TunnelType, const GUID* RequestedGUID);
        // Example placeholders (do not rely on these exact signaturers yet):
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr WintunCreateAdapter(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
            IntPtr requestGuid); // pass IntPtr.Zero or pointer to GUID (we'll warp this later if needed)

        // WINTUN_ADAPTER_HANDLE WintunOpenAdapter(const WCHAR* Name); 
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr WintunOpenAdapter(
            [MarshalAs(UnmanagedType.LPWStr)] string name);


        // void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter); 
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern void WintunCloseAdapter(IntPtr adapterHandle);

        // void WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID* Luid); 
        // NET_LUID is 64-bit on Windows; represented as ulong. 
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern void WintunGetAdapterLuid(IntPtr adapterHandle, out ulong luid);


        // ---- Session (packet I/O channel) ----

        //WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity); 
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr WintunStartSession(IntPtr adapterHandle, uint capacity);


        // void WintunEndSession(WINTUN_SESSION_HANDLE Session);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern void WintunEndSession(IntPtr sessionHandle);

        // HANDLE WintunGetReadEvent(WINTUN_SESSION_HANDLE Session);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr WintunGetReadEvent(IntPtr sessionHandle);

        // ---- Receive path ----

        // BYTE* WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD* PacketSize);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr WintunReceivePacket(IntPtr sessionHandle, out uint packetSize);

        // void WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern void WintunReleaseReceivePacket(IntPtr sessionHandle, IntPtr packet);

        // ---- Send path ----

        // BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr WintunAllocateSendPacket(IntPtr sessionHandle, uint packetSize);


        // void WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern void WintunSendPacket(IntPtr sessionHandle, IntPtr packet);

    }
}
