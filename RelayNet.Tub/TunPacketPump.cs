using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Tun
{
    /// <summary>
    /// Bridges the OS tunnel (TUN) with you client networking (RelayNetMux)
    /// Responsibility:
    /// - Read packets from TUN and forward them to mux/network. 
    /// - Read packets from mux/network and write them to TUN.
    /// 
    /// This is the "glue" that connects OS traffic to Relaynet. 
    /// </summary>
    public sealed class TunPacketPump
    {
        private readonly ITunDevice _tun;
        
        public TunPacketPump(ITunDevice tun)
        {
            _tun = tun;
        }

        /// <summary>
        /// Run the pump: 
        /// - tun -> onOutboundPacket
        /// - inboundPackets -> tun
        /// </summary>
        
        public async Task RunAsync(Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> onOutboundPacket,
            IAsyncEnumerable<ReadOnlyMemory<byte>> inboundPackets, CancellationToken ct)
        {
            // Task 1 Os -> RelayNet
            var readTask = Task.Run(async () =>
            {
        await foreach(var pkt in _tun.ReadPacketAsync(ct))
                {
                                   await onOutboundPacket(pkt, ct);
                }
            }, ct);

            // Task 2 RelayNet -> Os
            var writeTask = Task.Run(async () =>
            {
                await foreach (var pkt in inboundPackets.WithCancellation(ct))
                {
                    await _tun.WritePacketAsync(pkt, ct);
                }
            }, ct);

            await Task.WhenAll(readTask);
        }

    }
}
