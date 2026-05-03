using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace RelayNet.Tun.Windows
{
    /// <summary>
    /// Wintun-backed TUN device implementation.
    /// Responsibility: packet I/O lifecycle only (start/read/write/stop).
    /// Platform is responsible for adapter/network policy configuration.
    /// </summary>
    public sealed class WintunDevice : ITunDevice
    {
        private readonly TunConfig _config;

        private IntPtr _adapter = IntPtr.Zero;
        private IntPtr _session = IntPtr.Zero;
        private IntPtr _readEvent = IntPtr.Zero;

        public WintunDevice(TunConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public string Name => _config.AdapterName;

        public ValueTask StartAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            if (_session != IntPtr.Zero)
                return ValueTask.CompletedTask;

            _adapter = WintunNative.WintunOpenAdapter(_config.AdapterName);
            if (_adapter == IntPtr.Zero)
            {
                _adapter = WintunNative.WintunCreateAdapter(
                    _config.AdapterName,
                    _config.TunnelType,
                    IntPtr.Zero);
            }

            if (_adapter == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException(
                    $"Failed to open/create Wintun adapter '{_config.AdapterName}'. Win32 error: {err}");
            }

            _session = WintunNative.WintunStartSession(_adapter, _config.SessionCapacityBytes);
            if (_session == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;

                throw new InvalidOperationException(
                    $"Failed to start Wintun session for '{_config.AdapterName}'. Win32 error: {err}");
            }

            _readEvent = WintunNative.WintunGetReadWaitEvent(_session);
            if (_readEvent == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                WintunNative.WintunEndSession(_session);
                _session = IntPtr.Zero;

                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;

                throw new InvalidOperationException(
                    $"Failed to get Wintun read event for '{_config.AdapterName}'. Win32 error: {err}");
            }

            return ValueTask.CompletedTask;
        }

        public Task ConfigureAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            throw new NotSupportedException("Use ITunPlatform.ConfigureAsync for adapter policy configuration.");
        }

        public Task EnsureKillSwitchRulesExistAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            throw new NotSupportedException("Kill switch is implemented by platform policy (Phase 3/WFP).");
        }

        public Task EnableKillSwitchAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            throw new NotSupportedException("Kill switch is implemented by platform policy (Phase 3/WFP).");
        }

        public Task DisableKillSwitchAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            throw new NotSupportedException("Kill switch is implemented by platform policy (Phase 3/WFP).");
        }

        public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadPacketAsync([EnumeratorCancellation] CancellationToken ct)
        {
            EnsureStarted();

            const int ERROR_HANDLE_EOF = 38;
            const int ERROR_NO_MORE_ITEMS = 259;
            const int ERROR_INVALID_DATA = 13;

            using var readEvent = new AutoResetEvent(false);
            readEvent.SafeWaitHandle = new Microsoft.Win32.SafeHandles.SafeWaitHandle(_readEvent, ownsHandle: false);

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                IntPtr packetPtr = IntPtr.Zero;
                uint packetSize = 0;

                try
                {
                    packetPtr = WintunNative.WintunReceivePacket(_session, out packetSize);

                    if (packetPtr == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();

                        if (err == ERROR_NO_MORE_ITEMS)
                        {
                            int signaled = WaitHandle.WaitAny(new WaitHandle[] { readEvent, ct.WaitHandle });
                            if (signaled == 1)
                                ct.ThrowIfCancellationRequested();

                            continue;
                        }

                        if (err == ERROR_HANDLE_EOF)
                            yield break;

                        if (err == ERROR_INVALID_DATA)
                            throw new InvalidOperationException("Wintun receive buffer is corrupt.");

                        throw new Win32Exception(err);
                    }

                    byte[] managedPacket = new byte[packetSize];
                    Marshal.Copy(packetPtr, managedPacket, 0, (int)packetSize);
                    yield return managedPacket;
                }
                finally
                {
                    if (packetPtr != IntPtr.Zero)
                        WintunNative.WintunReleaseReceivePacket(_session, packetPtr);
                }
            }
        }

        public ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct)
        {
            EnsureStarted();
            ct.ThrowIfCancellationRequested();

            if (packet.Length == 0)
                return ValueTask.CompletedTask;

            IntPtr sendPtr = WintunNative.WintunAllocateSendPacket(_session, (uint)packet.Length);
            if (sendPtr == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"WintunAllocateSendPacket failed. Win32 error: {err}");
            }

            byte[] temp = packet.ToArray();
            Marshal.Copy(temp, 0, sendPtr, temp.Length);
            WintunNative.WintunSendPacket(_session, sendPtr);

            return ValueTask.CompletedTask;
        }

        public ValueTask StopAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            if (_session != IntPtr.Zero)
            {
                WintunNative.WintunEndSession(_session);
                _session = IntPtr.Zero;
            }

            _readEvent = IntPtr.Zero;

            if (_adapter != IntPtr.Zero)
            {
                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
            }

            return ValueTask.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await StopAsync(CancellationToken.None);
            }
            catch
            {
                // Ignore cleanup errors on disposal.
            }

            _readEvent = IntPtr.Zero;
            _session = IntPtr.Zero;
            _adapter = IntPtr.Zero;
        }

        private void EnsureStarted()
        {
            if (_session == IntPtr.Zero)
                throw new InvalidOperationException("Wintun session is not started. Call StartAsync first.");
        }
    }
}
