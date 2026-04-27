using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace RelayNet.Core.Networking
{

    public readonly record struct StreamProjection(
        uint StreamId,
        bool IsNewStream,
        bool ShouldCloseStream,
        InnerFrame Frame
        );

    /// <summary>
    /// Maps packet observations to logical stream ids. 
    ///  - TCP: one stream id per connection (both directions share one id). 
    ///  - UDP: one stream id per 5tuple association. 
    ///  
    ///  This does not create one id per packet; packets are only used to identity
    ///  which logical sream they belong to. 
    /// </summary>
    public sealed class PacketStreamMapper
    {
       private readonly Dictionary<LogicalStreamKey, uint> _streamIdsByKey = new();
       private uint _nextStreamId = 1;

        public bool TryProject(ReadOnlyMemory<byte> packet, out StreamProjection projection)
        { 
            projection = default;

            if(!PacketFlowParser.TryParsePacketFlowInfo(packet.Span, out var flow))
                return false;

            bool isNew = false;

            if (!_streamIdsByKey.TryGetValue(flow.StreamKey, out uint streamId))
            { 
                streamId = _nextStreamId++;
                _streamIdsByKey[flow.StreamKey] = streamId;
                isNew = true;
            }

            bool shouldclose = flow.IsTcp && (flow.IsTcpFin || flow.IsTcpRst);
            if(shouldclose)
                _streamIdsByKey.Remove(flow.StreamKey);

            //InnerType 1 = raw IP packet payload chunk for this logical stream. 
            var frame = new InnerFrame(streamId, InnerType: InnerFrameTypes.RawIpPacket, packet.ToArray());

            projection = new StreamProjection(StreamId: streamId, IsNewStream: isNew, ShouldCloseStream: shouldclose, Frame: frame);

            return true;
        }
        public int ActiveStreamCount => _streamIdsByKey.Count;
    }
}
