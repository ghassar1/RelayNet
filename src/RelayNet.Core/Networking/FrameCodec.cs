using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
namespace RelayNet.Core.Networking;

    public static class FrameCodec
    {
        public static async Task WriteAsync(NetworkStream stream, Frame frame, CancellationToken ct)
        { 
          var payloadLen = frame.Payload?.Length ?? 0;
          var bodyLen = 1 + payloadLen;

          Span<byte> header = stackalloc byte[4];
          BinaryPrimitives.WriteInt32BigEndian(header, bodyLen);

          await stream.WriteAsync(header.ToArray(), ct);

        // Write body [type][payload...]
        var body = new byte[bodyLen];
        body[0] = (byte)frame.Type;
        if(payloadLen > 0)
            Buffer.BlockCopy(frame.Payload!, 0, body, 1, payloadLen);

          await stream.WriteAsync(body, ct);
          await stream.FlushAsync(ct);

        }
        public static async Task<Frame> ReadAsync(NetworkStream stream, CancellationToken ct)
        {
            var lenBuf = await ReadExactAsync(stream, 4, ct);
            var bodyLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf);

            if ((bodyLen < 1 || bodyLen > 1024 * 1024)) // 1MB safety cap
                throw new InvalidOperationException($"Invalid frame length: {bodyLen}"); 

            var body = await ReadExactAsync(stream, bodyLen, ct);

            var type = (FrameType)body[0];
            var payload = bodyLen > 1 ? body[1..] : Array.Empty<byte>();

            return new Frame(type, payload);
        }
        private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count, CancellationToken ct)
        { 
            var buffer = new byte[count];   
            var offset = 0;

            while (offset < count)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct); 
                if (read == 0)
                    throw new Exception("Remote closed connection.");
                offset += read;
            }

            return buffer;
        }
    }


