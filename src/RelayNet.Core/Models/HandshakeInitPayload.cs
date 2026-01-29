using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Models
{
    public sealed record HandshakeInitPayload
    (
        byte[] ClientEcdhPublicKey,
        byte[] Challenge
    );
}
