using System;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Text;

namespace RelayNet.Tun.Windows
{
    /// <summary>
    /// Windows implementation of ITunDevice using Wintun. 
    /// Responsibility: 
    /// - Own adapter/session handles
    /// - Read packets from Wintun session
    /// - Write packets to Wintun session
    /// </summary>
    public sealed class WintunDevice : ITunDevice
    {
        private readonly TunConfig _config;

        // Native handles (placeholders until you implement actual Wintun session)
        private IntPtr _adapter = IntPtr.Zero;
        private IntPtr _session = IntPtr.Zero;
        private IntPtr _readEvent = IntPtr.Zero;

        // optional: prevent double start/stop 
        private int _started;  // 0/1 via Interlocked
        public WintunDevice(TunConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }
        public string Name => _config.AdapterName;

        public ValueTask StartAsync(CancellationToken ct)
        {
            // Create/open adaptor + start Winntun session (later)
            //Keep packet I/O concerns here.
            return ValueTask.CompletedTask;
        }
        public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadPacketAsync([System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct)
        {
            // TODO: Implement Wintun receive loop. 
            // Each yield return must be exactly one IP packet.
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(250, ct);
                yield break;
            }
        }

        public ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct)
        {
            // TODO: Implement Wintun send packet. 
            return ValueTask.CompletedTask;
        }

        public ValueTask StopAsync(CancellationToken ct)
        {
            // TODO: End Wintun session + close adapter handles.
            return ValueTask.CompletedTask;
        }
        public async ValueTask DisposeAsync()
        {
            try { await StopAsync(CancellationToken.None); } catch { /* ignore */}

            if (_adapter != IntPtr.Zero)
            {
                // WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
            }
        }
    }
}
