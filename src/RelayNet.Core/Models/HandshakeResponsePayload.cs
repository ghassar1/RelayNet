using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Models
{
    public sealed record HandshakeResponsePayload
    (
        byte[] RelayEcdhPublicKey,
        byte[] Signature // signature over (challenge + clientEcdhPublicKey)
    );
    
}
