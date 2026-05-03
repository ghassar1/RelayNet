using RelayNet.Tun.Windows.Native;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace RelayNet.Tun.Windows
{
    [SupportedOSPlatform("windows")]
    internal sealed class WfpPolicyManager
    {
        private static readonly Guid ProviderKey = Guid.Parse("c8bb876d-a96e-438f-a4af-117bb7715d41");

        private static readonly Guid SublayerKey = Guid.Parse("8f7eb31c-0064-4c5f-9baf-62d0efc0eb4c");
        private static readonly string FilterStatePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RelayNet", "wfp-filter-ids.txt");

        private readonly TunConfig _config;
        private WfpPolicyState _state = WfpPolicyState.Prepared;

        public WfpPolicyManager(TunConfig config) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public WfpPolicyState State => _state;

        public Task ApplyAsync(WfpBootsrapContext context, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            EnsureWindowsAndContext(context);

            IntPtr engine = IntPtr.Zero;
            bool txStarted = false;
            var createdFilterIds = new List<ulong>();

            try
            {
                engine = OpenEngine();
                BeginTransaction(engine);
                txStarted = true;

                EnsureProvider(engine);
                EnsureSublayer(engine);

                InstallBootstrapAllowFilters(engine, context, createdFilterIds);
                InstallWintunAllowAndDenyOthersFilters(engine, createdFilterIds);

                CommitTransaction(engine);
                txStarted = false;
                SaveManagedFilterIds(createdFilterIds);
                VerifyEnforcementState(createdFilterIds);
                _state = WfpPolicyState.Enforced;
              
            }
            catch
            {
                if (engine != IntPtr.Zero && txStarted)
                    AbortTransactionBerstEffort(engine);

                _state = WfpPolicyState.RolledBackl;
                throw;
            }
            finally {
                if (engine != IntPtr.Zero)
                    CloseEngineBestEffort(engine);
            }
            return Task.CompletedTask;
        }

        public Task RemoveAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            EnsureWindows();

            IntPtr engine = IntPtr.Zero;
            bool txStarted = false;
            try { 
                    engine = OpenEngine();
                    BeginTransaction(engine);
                    txStarted = true;

                RemoveManagedFilters(engine);
                RemoveSublayer(engine);
                RemoveProvider(engine);

                CommitTransaction(engine);
                txStarted = false;
                DeleteManagedFilterIdFile();
            }finally
            {
                if (engine != IntPtr.Zero && txStarted)
                    AbortTransactionBerstEffort(engine);

                if (engine != IntPtr.Zero)
                    CloseEngineBestEffort(engine);
            }

            _state = WfpPolicyState.Prepared;
            return Task.CompletedTask;
        }

        public Task CleanupStaleArtifactsAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            EnsureWindows();


            IntPtr engine = IntPtr.Zero;
            bool txStarted = false;
            try
            {
                engine = OpenEngine();
                BeginTransaction(engine);
                txStarted = true;

                RemoveManagedFilters(engine);
                RemoveSublayer(engine);
                RemoveProvider(engine);

                CommitTransaction(engine);
                txStarted = false;
                DeleteManagedFilterIdFile();
            }
            finally { 
                    if(engine != IntPtr.Zero && txStarted)
                        AbortTransactionBerstEffort(engine);

                    if (engine != IntPtr.Zero)
                        CloseEngineBestEffort(engine);
            }
            return Task.CompletedTask;
        }


        private static void EnsureWindowsAndContext(WfpBootsrapContext context)
        {
            EnsureWindows();
            ArgumentNullException.ThrowIfNull(context);

            if (!context.IsControlPlaneReady)
                throw new InvalidOperationException("Control plane is not ready according to the provided context.");
            if (context.RelayEndpointIps.Length == 0)
                throw new InvalidOperationException("At least one relay/control endpoint is required for bootsrap exceptions");
        }

        private static void EnsureWindows() {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on windows only.");
        }

        private static IntPtr OpenEngine()
        {
            var session = new WfpNative.FWPM_SESSION0
            {
                sessionKey = Guid.NewGuid(),
                displayData = new WfpNative.FWPM_DISPLAY_DATA0
                {
                    name = "RelayNet WEP Session",
                    description = "Relaynet outbound enforcment session"
                },
                flags = 0u,
                txnWaitTimeoutInMsec = 5000u, // check and handle the timeout
                processId = 0u,
                sid = IntPtr.Zero,
                username = string.Empty,
                kernelMode = false
            };

            int status = WfpNative.FwpmEngineOpen0(
     serverName: null!,
     authnService: WfpNative.RPC_C_AUTHN_WINNT,
     authIdentity: IntPtr.Zero,
     session: ref session,
     engineHandle: out IntPtr engine);


            if (status != WfpNative.ERROR_SUCCESS)
            throw new Win32Exception((int) status, "FwpmEngineOpen0 failed.");

        return engine;

    }

    private static void BeginTransaction(IntPtr engine)
        {
            int status = WfpNative.FwpmTransactionBegin0(engine, 0);
            if (status != WfpNative.ERROR_SUCCESS)
                throw new Win32Exception(status, "FwpmTransactionBegin0 failed.");
        }

        private static void CommitTransaction(IntPtr engine)
        {
            int status = WfpNative.FwpmTransactionCommit0(engine);
            if (status != WfpNative.ERROR_SUCCESS)
                throw new Win32Exception(status, "FwpmTransactionCommit0 failed.");
        }

        private static void EnsureProvider(IntPtr engine)
        {
            var provider = new WfpNative.FWPM_PROVIDER0
            {
                providerKey = ProviderKey,
                displayData = new WfpNative.FWPM_DISPLAY_DATA0
                {
                    name = "RelayNet  Provider",
                    description = "RelayNet WFP provider"
                },
                flags = 0u,
                providerData = IntPtr.Zero,
                serviceName = IntPtr.Zero
            };

            int status = WfpNative.FwpmProviderAdd0(engine, ref provider, IntPtr.Zero);

            if (status != WfpNative.ERROR_SUCCESS)
                return;
               if(status != unchecked((int)0x80320009)) // already exists
                throw new Win32Exception((int)status, "FwpmProviderAdd0 failed.");
        }
        private static void EnsureSublayer(IntPtr engine)
        {
            var sub = new WfpNative.FWPM_SUBLAYER0
            {
                subLayerKey = SublayerKey,
                displayData = new WfpNative.FWPM_DISPLAY_DATA0
                {
                    name = "RelayNet Sublayer",
                    description = "RelayNet outbound sublayer"
                },
                flags = 0u,
                providerKey = ProviderKey,
                providerData = default,
                weight = (ushort)0x7FFF
            };
            int status = WfpNative.FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero);
            if (status == WfpNative.ERROR_SUCCESS)
                return;
            if (status != unchecked((int)0x8032000A)) // already exists
                throw new Win32Exception((int)status, "FwpmSubLayerAdd0 failed.");
        }


        private static void InstallBootstrapAllowFilters(IntPtr engine, WfpBootsrapContext context, List<ulong> createdFilterIds)
        {
            foreach (string relayIp in context.RelayEndpointIps.Distinct(StringComparer.OrdinalIgnoreCase))
            { 
                if(!IPAddress.TryParse(relayIp, out IPAddress? ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    continue;

                IntPtr conditionPtr = IntPtr.Zero;
                IntPtr valuePtr = IntPtr.Zero;

                try
                {
                    var conditionValue = BuildRemoteAddressConditionValue(ip, out valuePtr);
                    var condition = new WfpNative.FWPM_FILTER_CONDITION0
                    {
                        // check overflow
                        fieldKey = WfpNative.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType = WfpNative.FWP_MATCH_EQUAL,
                        conditionValue = conditionValue
                    };

                    conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNative.FWPM_FILTER_CONDITION0>());
                    Marshal.StructureToPtr(condition, conditionPtr, false);

                    Guid layer = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                        ? WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V4
                        : WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V6;

                    var filter = new WfpNative.FWPM_FILTER0
                    {
                        filterKey = Guid.NewGuid(),
                        displayData = new WfpNative.FWPM_DISPLAY_DATA0
                        {
                            name = $"RelayNet Bootstrap Allow {relayIp}",
                            description = $"Allow relay/control endpoint before full outbound block"
                        },
                        flags = 0u,
                        providerKey = IntPtr.Zero,
                        providerData = default,
                        layerKey = layer,
                        subLayerKey = SublayerKey,
                        weight = new WfpNative.FWP_VALUE0 { type = WfpNative.FWP_EMPTY},
                        numFilterConditions = 1, 
                        filterCondition = conditionPtr,
                        action = new WfpNative.FWPM_ACTION0 { type = WfpNative.FWP_ACTION_PERMIT, filterType = Guid.Empty }
                    };
                    AddFilter(engine, ref filter, createdFilterIds);
                }
                finally {
                    if (conditionPtr != IntPtr.Zero) Marshal.FreeHGlobal(conditionPtr);
                    if (valuePtr != IntPtr.Zero) Marshal.FreeHGlobal(valuePtr);
                }
            }
        }

        private void InstallWintunAllowAndDenyOthersFilters(IntPtr engine, List<ulong> createdFilterIds)
        {
            int ifIndex = ResolveWintunInterfaceIndex(_config.AdapterName);

            var allowCondition = new WfpNative.FWPM_FILTER_CONDITION0
            { 
                fieldKey = WfpNative.FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType = WfpNative.FWP_MATCH_EQUAL,
                conditionValue = new WfpNative.FWP_CONDITION_VALUE0
                { 
                    type = WfpNative.FWP_UINT32, 
                    value = new WfpNative.FWP_CONDITION_VALUE0_UNION { uint32 = (uint)ifIndex }
                }
            }; 

            IntPtr allowPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNative.FWPM_FILTER_CONDITION0>());
            try {
                Marshal.StructureToPtr(allowCondition, allowPtr, false);

                AddAllowAndBlockPair(engine, WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V4, allowPtr, createdFilterIds);
                AddAllowAndBlockPair(engine, WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V6, allowPtr, createdFilterIds);

            }
            finally { 
             Marshal.FreeHGlobal(allowPtr);
            }
        }
        private static void AddAllowAndBlockPair(IntPtr engine, Guid layerKey, IntPtr allowConditionPtr, List<ulong> createdFilterIds) {
            var allowFilter = new WfpNative.FWPM_FILTER0
            {
                filterKey = Guid.NewGuid(),
                displayData = new WfpNative.FWPM_DISPLAY_DATA0 { name = "RelayNet Allow Wintun Egress", description = "Allow outbound connects on Wintun interface" },
                flags = 0u,
                providerKey = IntPtr.Zero,
                providerData = default,
                layerKey = layerKey,
                subLayerKey = SublayerKey,
                weight = new WfpNative.FWP_VALUE0 { type = WfpNative.FWP_UINT64, value = new WfpNative.FWP_VALUE0_UNION { uint64 = 100UL } },
                numFilterConditions = 1,
                filterCondition = allowConditionPtr,
                action = new WfpNative.FWPM_ACTION0 { type = WfpNative.FWP_ACTION_PERMIT, filterType = Guid.Empty },
            };
            AddFilter(engine, ref allowFilter, createdFilterIds);

            var blockFilter = new WfpNative.FWPM_FILTER0
            {
                filterKey = Guid.NewGuid(),
                displayData = new WfpNative.FWPM_DISPLAY_DATA0 { name = "RelayNet Block Non-Wintun Egress", description = "Block all remaining outbound connects" },
                flags = 0u,
                providerKey = IntPtr.Zero,
                providerData = default,
                layerKey = layerKey,
                subLayerKey = SublayerKey,
                weight = new WfpNative.FWP_VALUE0 { type = WfpNative.FWP_UINT64, value = new WfpNative.FWP_VALUE0_UNION { uint64 = 10UL } },
                numFilterConditions = 0,
                filterCondition = IntPtr.Zero,
                action = new WfpNative.FWPM_ACTION0 { type = WfpNative.FWP_ACTION_BLOCK, filterType = Guid.Empty },
            };
            AddFilter(engine, ref blockFilter, createdFilterIds);

        }

        private static WfpNative.FWP_CONDITION_VALUE0 BuildRemoteAddressConditionValue(IPAddress ip, out IntPtr valuePtr)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                byte[] mapped = new byte[16];
                bytes.CopyTo(mapped, 12);
                bytes = mapped;
            }

            var blob = new WfpNative.FWP_BYTE_ARRAY16 { byteArray16 = bytes };
            valuePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNative.FWP_BYTE_ARRAY16>());
            Marshal.StructureToPtr(blob, valuePtr, false);

            return new WfpNative.FWP_CONDITION_VALUE0
            {
                type = WfpNative.FWP_BYTE_ARRAY16_TYPE,
                value = new WfpNative.FWP_CONDITION_VALUE0_UNION { byteArray16 = valuePtr }
            };
         }
        private static void RemoveManagedFilters(IntPtr engine)
        {
            foreach (ulong id in LoadManagedFilterIds())
            {
                int status = WfpNative.FwpmFilterDeleteById0(engine, id); 
                if(status != WfpNative.ERROR_SUCCESS && status != unchecked((int)0x80320003))
                    throw new Win32Exception(status, $"FwpmFilterDeleteById0 failed for filter id {id}.");
            }
        }


        private static void RemoveSublayer(IntPtr engine)
        {
            Guid key = SublayerKey;
            int status = WfpNative.FwpmSubLayerDeleteByKey0(engine, ref key);
            if (status != WfpNative.ERROR_SUCCESS && status != unchecked((int)0x80320003)) // not found
                throw new Win32Exception((int)status, "FwpmSubLayerDeleteByKey0 failed.");
        }

        private static void RemoveProvider(IntPtr engine)
        {
            Guid key = ProviderKey;
            int status = WfpNative.FwpmProviderDeleteByKey0(engine, ref key);
            if (status != WfpNative.ERROR_SUCCESS && status != unchecked((int)0x80320003)) // not found
                throw new Win32Exception((int)status, "FwpmProviderDeleteByKey0 failed.");
        }

        private static int ResolveWintunInterfaceIndex(string adapterName)
        {
            NetworkInterface? nic =  NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => string.Equals(n.Name, adapterName, StringComparison.OrdinalIgnoreCase));

            if (nic is null)
                throw new InvalidOperationException("Could not resolve Wintun adapter for WFP egress filters.");

            int? index = nic.GetIPProperties()?.GetIPv6Properties()?.Index;
            if (!index.HasValue)
                throw new InvalidOperationException("Could not resolve Wintun IPv4 interface index for WFP egress filters.");

            return index.Value;
        }
        private static void AddFilter(IntPtr engine, ref WfpNative.FWPM_FILTER0 filter, List<ulong> createdFilterIds) {
            int status = WfpNative.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out ulong id);
            if (status != WfpNative.ERROR_SUCCESS)
                throw new Win32Exception(status, $"FwpmFilterAdd0 failed for filter '{filter.displayData.name}'.");

            createdFilterIds.Add(id);
        }
        private static void VerifyEnforcementState(IReadOnlyCollection<ulong> createdFilterIds) {
            if (createdFilterIds.Count < 4)
                throw new InvalidOperationException("WFP enforcement created too few filters; enforcement verification failed.");

                if (!File.Exists(FilterStatePath))
                throw new InvalidOperationException("WFP enforcement filter ID state file was not persisted.");

            int persisted = File.ReadAllLines(FilterStatePath).Count(line => !string.IsNullOrWhiteSpace(line));
            if (persisted != createdFilterIds.Count)
                throw new InvalidOperationException($"WFP enforcement filter persistence mismatch (expected {createdFilterIds.Count}, got {persisted}).");
        }
        private static IEnumerable<ulong> LoadManagedFilterIds()
        { 
            if(!File.Exists(FilterStatePath))
                return Array.Empty<ulong>();

            var ids = new List<ulong>();
            foreach (string line in File.ReadAllLines(FilterStatePath))
            { 
                if(ulong.TryParse(line, out ulong parsed))
                    ids.Add(parsed);
            }
            return ids;
        }

        private static void SaveManagedFilterIds(IEnumerable<ulong> ids)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilterStatePath)!);
            File.WriteAllLines(FilterStatePath, ids.Select(id => id.ToString()));
        }
        private static void DeleteManagedFilterIdFile()
        { 
            if(File.Exists(FilterStatePath))
                File.Delete(FilterStatePath);
        }
        private static void AbortTransactionBerstEffort(IntPtr engine)
        {
            _ = WfpNative.FwpmTransactionAbort0(engine);
        }
        private static void CloseEngineBestEffort(IntPtr engine)
        {
            _ = WfpNative.FwpmEngineClose0(engine);
        }
    } 
        internal enum WfpPolicyState
    {
        Prepared = 0,
        Enforced = 1,
        RolledBackl = 2,
    }

    public sealed class WfpBootsrapContext
    {
        public bool IsControlPlaneReady { get; init; }
        public string[] RelayEndpointIps { get; init; } = Array.Empty<string>();

    }
}
