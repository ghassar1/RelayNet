using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace RelayNet.Tun.Windows.Native
{
    internal static class WfpNative
    {
        private const string DllName = "fwpuclnt.dll";

        internal const int RPC_C_AUTHN_WINNT = 10;
        internal const int ERROR_SUCCESS = 0;
        internal const int FWP_ACTION_BLOCK = 0x00000001;
        internal const int FWP_ACTION_PERMIT = 0x00000002;
        internal const uint FWP_EMPTY = 0;
        internal const uint FWP_UINT8 = 1;
        internal const uint FWP_UINT16 = 2;
        internal const uint FWP_UINT32 = 3;
        internal const uint FWP_UINT64 = 4;
        internal const uint FWP_BYTE_ARRAY16_TYPE = 11;

        internal const uint FWP_MATCH_EQUAL = 0;

        internal static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        internal static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        internal static readonly Guid FWPM_CONDITION_IP_LOCAL_INTERFACE = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");

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
            public uint txnWaitTimeoutInMsec;
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


        [StructLayout(LayoutKind.Sequential)]
        internal struct FWP_VALUE0
        {
            public uint type;
            public FWP_VALUE0_UNION value;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct  FWP_VALUE0_UNION
        {
            [FieldOffset(0)] public byte uint8;
            [FieldOffset(0)] public ushort uint16;
            [FieldOffset(0)] public uint uint32;
            [FieldOffset(0)] public uint uint64;
            [FieldOffset(0)] public IntPtr byteArray16;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWP_CONDITION_VALUE0
        {
            public uint type;
            public FWP_CONDITION_VALUE0_UNION value;
        }


        [StructLayout(LayoutKind.Explicit)]
        internal struct FWP_CONDITION_VALUE0_UNION {
            [FieldOffset(0)] public byte uint8;
            [FieldOffset(0)] public ushort uint16;
            [FieldOffset(0)] public uint uint32;
            [FieldOffset(0)] public uint uint64;
            [FieldOffset(0)] public IntPtr byteArray16;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_ACTION0 {
            public uint type;
            public Guid filterType;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWP_BYTE_ARRAY16 {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] byteArray16;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_FILTER_CONDITION0 {
            public Guid fieldKey;
            public uint matchType;
            public FWP_CONDITION_VALUE0 conditionValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FWPM_FILTER0 {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWP_VALUE0 weight;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public FWPM_ACTION0 action;
            public ulong reserved;
            public IntPtr effectiveWeight;
        }

        [DllImport(DllName, CharSet = CharSet.Unicode)]
        internal static extern int FwpmEngineOpen0(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            int authnService,
            IntPtr authIdentity,
            ref FWPM_SESSION0 session,
            out IntPtr engineHandle);
      
         [DllImport(DllName)]
         internal static extern int FwpmEngineClose0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern int FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport(DllName)]
        internal static extern int FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern int FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport(DllName)]
        internal static extern int FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

        [DllImport(DllName)]
        internal static extern int FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

        [DllImport(DllName)]
        internal static extern int FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport(DllName)]
        internal static extern int FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);
        [DllImport(DllName)]
        internal static extern int FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);
        [DllImport(DllName)]
        internal static extern int FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    }
}
