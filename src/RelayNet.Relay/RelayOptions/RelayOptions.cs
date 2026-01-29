using System;
using System.Collections.Generic;
using System.Text;

namespace RelayNet.Relay
{
    public sealed class RelayOptions
    {
        public string ListenAddress { get; init; } = "127.0.0.1"; 
        public int ListenPort { get; init; } = 9001;
        public string Role { get; init; } = "Entry"; 

        public string? NextHop { get; init; }
    }
}
