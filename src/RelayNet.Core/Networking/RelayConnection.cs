using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace RelayNet.Core.Networking
{
    /// <summary>
    ///  Represents a persistent TCP connection to a relay. 
    ///  Provides methods to send and recive framed messages. 
    ///  Can be used on both client and relay side
    /// </summary>
    public sealed class RelayConnection : IAsyncDisposable
    {
        private readonly TcpClient _client; 
        public NetworkStream Stream { get; private set; }

        //ADDED: Session is optional until handshake completes
        public RelaySession? Session { get; set; }


        private RelayConnection(TcpClient client)
        {
            _client = client;
            Stream = client.GetStream();
        }
        /// <summary>
        /// Establish a TCP connection to a host:port.
        /// </summary>
        public static async Task<RelayConnection> ConnectAsync(string host, int port)
        { 
            var client = new TcpClient();
            await client.ConnectAsync(host, port);
            return new RelayConnection(client);
        }


        /// <summary>
        /// Sends a frame over the connection.
        /// Encrypts payload ONLY for data frames afterhandshake completes
        /// </summary>
        public async Task SendFrameAsync(Frame frame, CancellationToken ct = default)
        {
            //Only data frames require encryption
            bool requireEncryption = frame.Type == FrameType.Data;

            if (requireEncryption)
            {
                if (Session?.State != ConnectionState.HandshakeComplete)
                    throw new InvalidOperationException("Handshake not completed; cannot send frames.");

                if (Session?.SessionKey == null)
                    throw new InvalidOperationException("Session key missing, cannot send frame.");
            }

            byte[] payloadToSend;

            if (!requireEncryption)
                payloadToSend = frame.Payload ?? Array.Empty<byte>();
            else {
                // Encrypt payload using ASE-GCM
                byte[] plaintext = frame.Payload ?? Array.Empty<byte>();
                byte[] iv = RandomNumberGenerator.GetBytes(12); // 12-byte GCM IV 
                byte[] ciphertext = new byte[plaintext.Length + 12 + 16]; // IV + ciphertext + tag
                byte[] tag = new byte[16];
                using var aes = new AesGcm(Session.SessionKey, AesGcm.TagByteSizes.MaxSize);

                aes.Encrypt(
                    iv,
                    plaintext,
                    ciphertext,
                    tag,
                    new[] { (byte)frame.Type }
                );

                payloadToSend = new byte[iv.Length + ciphertext.Length + tag.Length];
                Buffer.BlockCopy(iv, 0, payloadToSend, 0, iv.Length);
                Buffer.BlockCopy(ciphertext, 0, payloadToSend, iv.Length, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, payloadToSend, iv.Length + ciphertext.Length, tag.Length);
            }



            var bodyLen = 1 + payloadToSend.Length;
            Span<byte> header = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(header, bodyLen);
            await Stream.WriteAsync(header.ToArray(), ct);

            // Send encrypted payload (not plaintext)
            var body = new byte[bodyLen];
            body[0] = (byte)frame.Type;
            Buffer.BlockCopy(frame.Payload!, 0, body, 1, payloadToSend.Length);

            await Stream.WriteAsync(body, ct);
            await Stream.FlushAsync(ct);
        }

        /// <summary>
        /// Reads a frame from the connection.
        /// Decrypts payload ONLY for data frames after handshake completes.
        /// </summary>
        public async Task<Frame> ReceiveFrameAsync(CancellationToken ct = default)
        {
            var lenBuf = await ReadExactAsync(Stream, 4, ct);
            var bodyLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf);

            if (bodyLen < 1 || bodyLen > 1024 * 1024) // 1MB safety cap
                throw new InvalidOperationException($"Invalid frame length: {bodyLen}");

            var body = await ReadExactAsync(Stream, bodyLen, ct);

            var type = (FrameType)body[0];
            var payload = bodyLen > 1 ? body[1..] : Array.Empty<byte>();

            //Prevent handshake frames after handshake completion
            if (Session?.State == ConnectionState.HandshakeComplete &&
                (type == FrameType.Handshake ||
                 type == FrameType.Challenge ||
                 type == FrameType.ChallengeResponse ||
                 type == FrameType.HandshakeInit ||
                 type == FrameType.HandshakeResponse))
            {
                await DisposeAsync();
                throw new InvalidOperationException("Handshake frames are not allowed after handshake completion.");
            }

            bool requiresDecryption = type == FrameType.Data;

            if (!requiresDecryption)
                return new Frame(type, payload);

            if (Session?.State != ConnectionState.HandshakeComplete)
                throw new InvalidOperationException("Handshake not completed; cannot send frames.");

            if (Session?.SessionKey == null)
                throw new InvalidOperationException("Session key missing, cannot send frame.");

            // Decrypt payload using AES-GCM
            if (payload.Length < 12 + 16)
                throw new InvalidOperationException("Invalid encrypted frame length");

            try
            {

                byte[] iv = payload[..12];
                byte[] tag = payload[^16..];
                byte[] encrypted = payload[12..^16];
                byte[] decrypted = new byte[encrypted.Length];

                using var aes = new AesGcm(Session.SessionKey, AesGcm.TagByteSizes.MaxSize);
                aes.Decrypt(iv, encrypted, tag, decrypted, new[] { (byte)type });

                return new Frame(type, decrypted);
            }
            catch (CryptographicException ex)
            {
                await DisposeAsync();
                throw new InvalidOperationException("Failed to decrypt frame payload.", ex);

            }
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
        private async Task SendRawAsync(Frame frame, CancellationToken ct)
        { 
            await FrameCodec.WriteAsync(Stream, frame, ct);
        }
        private async Task<Frame> ReceiveRawAsync(CancellationToken ct)
        { 
            return await FrameCodec.ReadAsync(Stream, ct);
        }
        // / <summary>
        /// Closes the connection and disposes the stream.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
           if(Stream != null)
                await Stream.DisposeAsync();
           _client.Close();
        }
    }
}
