using System;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using RelayNet.Core.Networking;
using RelayNet.Tun;
using RelayNet.Tun.Windows;

namespace RelayNet.Tun.Test
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var config = new TunConfig
            {
                AdapterName = "RelayNet",
                AddressCidrV4 = "10.10.0.2/24",
                GatewayV4 = "10.10.0.1",
                AddressCidrV6 = "fd00::2/64",
                GatewayV6 = "fd00::1",
                DnsServers = new[] { "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2606:4700:4700::1001" }
            };
            var platform = new WindowsTunPlatform();
            var device = await platform.CreateOrOpenAsync(config, CancellationToken.None);
            await device.StartAsync(CancellationToken.None);
            await platform.ConfigureAsync(device, config, CancellationToken.None);

            // Kill-switch is implemented in Phase 3 (WEP)

            // NEW: stream-aware grouping + wrapping before packets leave the client
            var mux = new RelayNetMux();

            Console.WriteLine("Capturing packets and grouping by logical stream...\n");

            await foreach (var pkt in device.ReadPacketAsync(CancellationToken.None))
            {
                Console.WriteLine($"Packet: {pkt.Length} bytes");
                if (!mux.TryWrapOutbound(pkt, out var projection, out var relayPayload)) {
                    Console.WriteLine($"Ignored packet ({pkt.Length} bytes): non-IPv4 TCP/UDP");
                    continue;
                }

                // Optional debug: deocde back to show wrapper carries strea id. 

                var decoded = mux.UnwrapInbound(relayPayload);

                Console.WriteLine($"Stream={projection.StreamId} " +
                    $"New={projection.IsNewStream} " +
                    $"Close={projection.ShouldCloseStream} " +
                    $"PacketBytes={pkt.Length} " +
                    $"RelayPayloadBytes={relayPayload.Length} " +
                    $"ActiveStreams={mux.ActiveStreamCount} " +
                    $"DecodedStrean={decoded.StreamId} " 
                    );
            }
        }
    }
}