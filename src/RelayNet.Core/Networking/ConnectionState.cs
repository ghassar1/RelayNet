using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Core.Networking
{
    public enum ConnectionState
    {
        Connecting, 
        Hadshaking,
        HandshakeComplete,
        Closed
    }
}
