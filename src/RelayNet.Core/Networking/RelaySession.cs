using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking
{
    public sealed class RelaySession
    {
        public byte[] SessionKey { get; set; }
        public ConnectionState State { get; set; } = ConnectionState.HandshakeComplete;

        // Optional additional session info
        public byte[]? ClientEphemeralPublicKey { get; set; }
        public byte[]? RelayEphemeralPublicKey { get; set; }
        public byte[]? Challenge { get; set; }
        public byte[]? ChallengeSignature { get; set; }

        // Timestamp or other metadata
        public DateTime HandshakeStarted { get; set; } = DateTime.UtcNow;
    }
}
