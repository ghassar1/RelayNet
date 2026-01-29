using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking;

    public enum FrameType : byte 
    {
        Ping = 1,
        Pong = 2,
        Echo = 3,
        EchoReplay = 4,
        Forward = 5,
        Handshake = 6,
        Challenge = 7,
        ChallengeResponse = 8,
        HandshakeInit = 10,
        HandshakeResponse = 11,
        //Only after handshake
        SecureData = 12,
        Data = 13,
    
}

