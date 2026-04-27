using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking
{
    public readonly record struct FlowEndpoint(uint IpV4, ushort Port);
    /// <summary>
    /// Direction-agnostic logical stream key. 
    /// Both A->B nd B->A map tp the same key.
    /// </summary>
    /// 
    public readonly record struct LogicalStreamKey(
        byte Protocol, 
        FlowEndpoint SideA, 
        FlowEndpoint SideB
        );

    public readonly record struct PacketFlowInfo(
        LogicalStreamKey StreamKey,
        bool IsTcp, 
        bool IsTcpSyn,
        bool IsTcpAck, 
        bool IsTcpFin,
        bool IsTcpRst
        );
    public static class PacketFlowParser
    {
        // Minimal parser for IPv4 TCP/UDP packets from TUN. 
        // We still parse packets at ingress, bt stream identity is logical-connection based. 
        public static bool TryParsePacketFlowInfo(ReadOnlySpan<byte> packet, out PacketFlowInfo info)
        {
            info = default;

            if (packet.Length < 20)
                return false;

            byte version = (byte)(packet[0] >> 4);
            if (version != 4)
                return false;

            int ihlBytes = (packet[0] & 0x0f) * 4;
            if (ihlBytes < 20 || packet.Length < ihlBytes + 4)
                return false;

            byte protocol = packet[9];
            if (protocol != 6 && protocol != 17) // TCP/UDP
                return false;

            uint srcIp = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
            uint destIp = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihlBytes, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihlBytes + 2, 2));

            var src = new FlowEndpoint(srcIp, srcPort);
            var dst = new FlowEndpoint(destIp, dstPort);
            var key = Canonicalize(protocol, src, dst);

            bool isTcp = protocol == 6;
            bool syn = false, ack = false, fin = false, rst = false;

            if (isTcp)
            { 
            if(packet.Length < ihlBytes + 14)
                    return false;

            byte flags = packet[ihlBytes + 13];
              syn = (flags & 0x02) != 0;
              ack = (flags & 0x10) != 0;
              fin = (flags & 0x01) != 0;
              rst = (flags & 0x04) != 0;
            }

            info = new PacketFlowInfo(
                key,
                 IsTcp: isTcp,
         IsTcpSyn: syn,
         IsTcpAck: ack,
         IsTcpFin: fin,
         IsTcpRst: rst);
            return true;

        }
        private static LogicalStreamKey Canonicalize(byte protocol, FlowEndpoint left, FlowEndpoint right)
        {
            // Stable ordering so both directions share one stram id.
            bool leftFirst = IsLessOrEqual(left, right);
            return leftFirst ? new LogicalStreamKey(protocol, left, right)
                : new LogicalStreamKey(protocol, right, left);
        }

        private static bool IsLessOrEqual(FlowEndpoint a, FlowEndpoint b)
        {
            if (a.IpV4 != b.IpV4)
                return a.IpV4 < b.IpV4;

            return a.Port <= b.Port;
        }
    }
    }
