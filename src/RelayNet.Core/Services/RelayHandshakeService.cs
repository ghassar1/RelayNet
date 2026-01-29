using RelayNet.Core.Networking;
using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Text;

namespace RelayNet.Core.Services
{
    public class RelayHandshakeService
    {
        private readonly byte[] _identityPrivateKeyBytes; 

        public RelayHandshakeService(byte[] identityPrivateKeyBytes)
        {
            _identityPrivateKeyBytes = identityPrivateKeyBytes;
        }

        public async Task<byte[]> HandleHandshakeAsync(RelayConnection conn, 
            CancellationToken ct = default)
        { 
           //Recive Client's ephemeral public key
           var clientKeyFrame = await conn.
        }
    }
}
