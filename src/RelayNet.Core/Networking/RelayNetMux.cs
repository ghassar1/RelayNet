using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking
{
    /// <summary>
    /// Wrap one observed TUN packet into a stream aware relay payload.
    /// Returns false if packet is not IPv4 TCP/UDP.
    /// </summary>
    /// 
    public sealed class RelayNetMux
    {
        private readonly PacketStreamMapper _mapper = new();

        public bool TryWrapOutbound(ReadOnlyMemory<byte> packet, out StreamProjection projection, out byte[] relayPayload)
        { 
           relayPayload = Array.Empty<byte>();

            if(!_mapper.TryProject(packet, out projection))
                return false;

            relayPayload = InnerFrameCodec.Encode(projection.Frame);
            return true;
        }

        /// <summary>
        /// Decode inbound relay payload into an inner frame. 
        /// Caller can then route by StreamId and write payload back to TUN if type is RawIpPacket.
        /// </summary>
        
        public InnerFrame UnwrapInbound(ReadOnlySpan<byte> relayPayload)
            => InnerFrameCodec.Decode(relayPayload);

        public int ActiveStreamCount => _mapper.ActiveStreamCount;
    }
}
