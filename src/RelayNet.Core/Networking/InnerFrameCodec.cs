using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking
{
    public static class InnerFrameCodec
    {
        // Wire format: [streamId:4][innerType:1][payload:N]
        public static byte[] Encode(InnerFrame frame)
        {
            int payloadLen = frame.Payload?.Length ?? 0;
            byte[] bytes = new byte[5 + payloadLen];

            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(0, 4), frame.StreamId);
            bytes[4] = frame.InnerType;

            if (payloadLen > 0)
                Buffer.BlockCopy(frame.Payload!, 0, bytes, 5, payloadLen);

            return bytes;
        }

        public static InnerFrame Decode(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < 5)
                throw new InvalidOperationException("Inner frame too short.");

            uint streamId = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(0, 4));
            byte innerType = bytes[4];
            byte[] payload = bytes.Slice(5).ToArray();

            return new InnerFrame(streamId, innerType, payload);
        }
    }
}
