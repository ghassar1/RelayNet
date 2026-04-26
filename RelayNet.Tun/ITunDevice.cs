using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.CompilerServices;

namespace RelayNet.Tun
{
    /// <summary>
    /// A running TUN device session. 
    /// Responibility: packet I/O only (read/write IP packets).
    /// It does NOT configure IP/DNS/routes (platform does that).
    /// </summary>
    public interface ITunDevice : IAsyncDisposable
    {
        string Name { get; }

        /// <summary>Start underlyning session handles/resources.</summary>
        ValueTask StartAsync (CancellationToken ct);
        Task ConfigureAsync(CancellationToken ct);
        /// <summary>Stop session handles/resources.</summary>
        ValueTask StopAsync(CancellationToken ct);

        Task EnsureKillSwitchRulesExistAsync(CancellationToken ct);
        Task EnableKillSwitchAsync(CancellationToken ct);
        /// <summary>
        /// Reads raw IP packets from the OS (each item is a single packet)
        /// </summary>
        /// 
        IAsyncEnumerable<ReadOnlyMemory<byte>> ReadPacketAsync(CancellationToken ct);

        /// <summary>
        /// Writes a raw IP packet back to the OS.
        /// </summary>
        ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct);
    }
}
