using System;
using System.Runtime.InteropServices;

namespace RelayNet.Tun.Windows.Native
{
    internal static class WfpNative
    {
        private const string DllName = "fwpuclnt.dll";

        internal const uint RPC_C_AUTHN_WINNT = 10;
        internal const uint ERROR_SUCCESS = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FWPM_DISPLAY_DATA0
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string name;
            [MarshalAs(UnmanagedType.LPWStr)] public string description;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_SESSION0
        {
            public Guid sessionKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public uint txnWaitTimeoutInMSec;
            public uint processId;
            public IntPtr sid;
            [MarshalAs(UnmanagedType.LPWStr)] public string username;
            public bool kernelMode;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_PROVIDER0
        {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerData;
            public IntPtr serviceName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWP_BYTE_BLOB
        {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_SUBLAYER0
        {
            public Guid subLayerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public Guid providerKey;
            public FWP_BYTE_BLOB providerData;
            public ushort weight;
        }

        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern uint FwpmEngineOpen0(
            string serverName,
            uint authnService,
            IntPtr authIdentity,
            ref FWPM_SESSION0 session,
            out IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport(DllName)]
        internal static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

        [DllImport(DllName)]
        internal static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);
    }
}
