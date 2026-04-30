using RelayNet.Tun.Windows.Native;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.Versioning;
using System.Text;

namespace RelayNet.Tun.Windows
{
    [SupportedOSPlatform("windows")]
    internal sealed class WfpPolicyManager
    {
        private static readonly Guid ProviderKey = Guid.Parse("c8bb876d-a96e-438f-a4af-117bb7715d41");

        private static readonly Guid SublayerKey = Guid.Parse("8f7eb31c-0064-4c5f-9baf-62d0efc0eb4c");

        private readonly TunConfig _config;
        private WfpPolicyState _state = WfpPolicyState.Prepared;

        public WfpPolicyManager(TunConfig config) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public WfpPolicyState State => _state;

        public Task ApplyAsync(WfpBootsrapContext context, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on windows only.");

            if (!context.IsControlPlaneReady)
                throw new InvalidOperationException("Control-plane handshake is not ready; refusing to enforce WFP egress policy.");

            if (context.RelayEndpointIps.Length == 0)
                throw new InvalidOperationException("At least one relay/control endpoint is required for bootstrap exceptions.");

            IntPtr engine = IntPtr.Zero;
            bool txStarted = false;

            try
            {
                engine = OpenEngine();
                BeginTransaction(engine);
                txStarted = true;

                EnsureProvider(engine);
                EnsureSublayer(engine);

                InstallBootstrapAllowFilters(engine, context);
                InstallWintunAllowAndDenyOthersFilters(engine);

                CommitTransaction(engine);
                txStarted = false; 
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
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported in Windows only.");

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
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WFP policy management is supported on windows only.");


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
            }
            finally { 
                    if(engine != IntPtr.Zero && txStarted)
                        AbortTransactionBerstEffort(engine);

                    if (engine != IntPtr.Zero)
                        CloseEngineBestEffort(engine);
            }
            return Task.CompletedTask;
        }

        private static IntPtr OpenEngine()
        {
            var session = new WfpNative.FWPM_SESSION0
            {
                sessionKey = Guid.NewGuid(),
                displayData = new WfpNative.FWPM_DISPLAY_DATA0
                {
                    name = "RelayNet Tun Session",
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
            int status = WfpNative.FwpmTransactionBegin0(engine, 0u);
            if (status != WfpNative.ERROR_SUCCESS)
                throw new Win32Exception((int)status, "FwpmTransactionBegin0 failed.");
        }

        private static void CommitTransaction(IntPtr engine)
        {
            int status = WfpNative.FwpmTransactionCommit0(engine);
            if (status != WfpNative.ERROR_SUCCESS)
                throw new Win32Exception((int)status, "FwpmTransactionCommit0 failed.");
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
            if (status != WfpNative.ERROR_SUCCESS && status != 0x80320009) // already exists
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
            {
                // Created by current apply transaction.
            }
            else if (status != unchecked((int)0x8032000A)) // already exists
            {
                throw new Win32Exception((int)status, "FwpmSubLayerAdd0 failed.");
            }
        }


        private static void InstallBootstrapAllowFilters(IntPtr engine, WfpBootsrapContext context)
        {
            // Hook for real endpoint-scoped allow filters. 
            // We validate presence of endpoints at ApplyAsync entry; concrete filter installation
            // is added in next strict interop iteration.

            _ = engine; 
            _ = context;
        }

        private static void InstallWintunAllowAndDenyOthersFilters(IntPtr engine)
        {
            // Hook for real wintun allow and block-others filters.
            _ = engine;
        }

        private static void RemoveManagedFilters(IntPtr engine)
        {
            // Hook for deleting known filter IDs created by this manager.
            _ = engine;
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