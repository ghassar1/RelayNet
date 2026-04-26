using System;
using System.Threading;
using System.Threading.Tasks;
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
            await device.ConfigureAsync(CancellationToken.None);

            await device.EnsureKillSwitchRulesExistAsync(CancellationToken.None);

            // only when you want strict no-bypass mode
            await device.EnableKillSwitchAsync(CancellationToken.None);

            await foreach (var pkt in device.ReadPacketAsync(CancellationToken.None))
            {
                Console.WriteLine($"Packet: {pkt.Length} bytes");
            }
        }
    }
}