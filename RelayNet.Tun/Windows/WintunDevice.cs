using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace RelayNet.Tun.Windows
{
    /// <summary>
    /// Windows implementation of ITunDevice using Wintun.
    /// Responsibility:
    /// - Own the native Wintun adapter/session handles
    /// - Start the virtual adapter session
    /// - Read raw IP packets from Wintun
    /// - Write raw IP packets to Wintun
    ///
    /// This class is packet I/O only.
    /// It does not configure adapter IP/DNS/routes; that belongs to WindowsTunPlatform.
    /// It does not perform framing, multiplexing, or encryption; that belongs to a higher layer.
    /// </summary>
    public sealed class WintunDevice : ITunDevice
    {
        private readonly TunConfig _config;

        // Native handles (placeholders until you implement actual Wintun session)

        // Native Wintun adapter handle.
        // Represents the virtual network adapter itself.
        private IntPtr _adapter = IntPtr.Zero;

        // Native Wintun session handle.
        // Represents the active packet I/O session for this adapter.
        private IntPtr _session = IntPtr.Zero;

        // Native read event handle returned by Wintun.
        // Used later to wait until packets are available to read.
        private IntPtr _readEvent = IntPtr.Zero;
        private IntPtr _readWaitEvent = IntPtr.Zero;
        public WintunDevice(TunConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }
        public string Name => _config.AdapterName;



        /// <summary>
        /// Initializes the Wintun device session for this adapter.
        ///
        /// This is the first method that should be called on WintunDevice
        /// before attempting to read or write packets.
        ///
        /// Steps:
        /// 1) Try to open an existing adapter by name
        /// 2) If not found, create a new adapter
        /// 3) Start a Wintun session on that adapter
        /// 4) Obtain the read event handle used by the receive path
        ///
        /// This method prepares packet I/O only.
        /// It does not read packets yet; actual packet capture happens in ReadPacketAsync.
        /// </summary>
        public ValueTask StartAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            // Already started.
            if (_session != IntPtr.Zero)
                return ValueTask.CompletedTask;

            // Clear stale field just in case.
            _readEvent = IntPtr.Zero;

            // 1) Try to open an existing adapter first.
            _adapter = WintunNative.WintunOpenAdapter(_config.AdapterName);

            // 2) If it does not exist, create it.
            if (_adapter == IntPtr.Zero)
            {
                _adapter = WintunNative.WintunCreateAdapter(
                    _config.AdapterName,
                    _config.TunnelType,
                    IntPtr.Zero);
            }

            // 3) If open/create failed, stop.
            if (_adapter == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException(
                    $"Failed to open or create Wintun adapter '{_config.AdapterName}'. Win32 error: {err}");
            }

            // 4) Start packet I/O session.
            _session = WintunNative.WintunStartSession(
                _adapter,
                _config.SessionCapacityBytes);

            if (_session == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();

                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;

                throw new InvalidOperationException(
                    $"Failed to start Wintun session for adapter '{_config.AdapterName}'. Win32 error: {err}");
            }

            // 5) Get session read-wait event.
            _readEvent = WintunNative.WintunGetReadWaitEvent(_session);

            if (_readEvent == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();

                WintunNative.WintunEndSession(_session);
                _session = IntPtr.Zero;

                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;

                throw new InvalidOperationException(
                    $"Failed to get Wintun read-wait event for adapter '{_config.AdapterName}'. Win32 error: {err}");
            }

            return ValueTask.CompletedTask;
        }
        public async Task ConfigureAsync(CancellationToken ct)
        {
            var (ipv4, prefix4) = ParseCidr(_config.AddressCidrV4);
            var (ipv6, prefix6) = ParseCidr(_config.AddressCidrV6);

            string adapterName = _config.AdapterName.Replace("'", "''");
            string gateway4 = _config.GatewayV4.Replace("'", "''");
            string gateway6 = _config.GatewayV6.Replace("'", "''");

            await RunPowerShellAsync(
                $"New-NetIPAddress -InterfaceAlias '{adapterName}' -IPAddress '{ipv4}' -PrefixLength {prefix4}",
                ct);

            await RunPowerShellAsync(
                $"New-NetIPAddress -InterfaceAlias '{adapterName}' -IPAddress '{ipv6}' -PrefixLength {prefix6}",
                ct);

            if (_config.DnsServers is { Length: > 0 })
            {
                string dnsList = string.Join(",", _config.DnsServers.Select(d => $"'{d.Replace("'", "''")}'"));

                await RunPowerShellAsync(
                    $"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ServerAddresses {dnsList}",
                    ct);
            }

            await RunPowerShellAsync(
                $"New-NetRoute -InterfaceAlias '{adapterName}' -DestinationPrefix '0.0.0.0/0' -NextHop '{gateway4}'",
                ct);

            await RunPowerShellAsync(
                $"New-NetRoute -InterfaceAlias '{adapterName}' -DestinationPrefix '::/0' -NextHop '{gateway6}'",
                ct);
        }
        public async Task EnableKillSwitchAsync(CancellationToken ct)
        {
            var aliases = await GetNonTunnelAdapterAliasesAsync(ct);

            foreach (var alias in aliases)
            {
                string safeAlias = alias.Replace("'", "''");
                string ruleName = GetKillSwitchRuleName(alias).Replace("'", "''");

                await RunPowerShellAsync(
                    $"if (-not (Get-NetFirewallRule -DisplayName '{ruleName}' -ErrorAction SilentlyContinue)) " +
                    $"{{ New-NetFirewallRule -DisplayName '{ruleName}' -Direction Outbound -Action Block -InterfaceAlias '{safeAlias}' -Enabled True }} " +
                    $"else {{ Enable-NetFirewallRule -DisplayName '{ruleName}' }}",
                    ct);
            }
        }
        public async Task EnsureKillSwitchRulesExistAsync(CancellationToken ct)
        {
            var aliases = await GetNonTunnelAdapterAliasesAsync(ct);

            foreach (var alias in aliases)
            {
                string safeAlias = alias.Replace("'", "''");
                string ruleName = GetKillSwitchRuleName(alias).Replace("'", "''");

                await RunPowerShellAsync(
                    $"if (-not (Get-NetFirewallRule -DisplayName '{ruleName}' -ErrorAction SilentlyContinue)) " +
                    $"{{ New-NetFirewallRule -DisplayName '{ruleName}' -Direction Outbound -Action Block -InterfaceAlias '{safeAlias}' -Enabled False }}",
                    ct);
            }
        }
        public async Task DisableKillSwitchAsync(CancellationToken ct)
        {
            await RunPowerShellAsync(
                "Get-NetFirewallRule -DisplayName 'RelayNet KillSwitch *' -ErrorAction SilentlyContinue | Disable-NetFirewallRule",
                ct);
        }

        private static string GetKillSwitchRuleName(string alias)
            => $"RelayNet KillSwitch {alias}";
        public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadPacketAsync(
         [EnumeratorCancellation] CancellationToken ct)
        {
            if (_session == IntPtr.Zero)
                throw new InvalidOperationException("Wintun session is not started. Call StartAsync first.");

            const int ERROR_HANDLE_EOF = 38;
            const int ERROR_NO_MORE_ITEMS = 259;
            const int ERROR_INVALID_DATA = 13;

            using var readEvent = new AutoResetEvent(false);
            readEvent.SafeWaitHandle = new Microsoft.Win32.SafeHandles.SafeWaitHandle(_readEvent, ownsHandle: false);

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                IntPtr packetPtr = IntPtr.Zero;
                uint packetSize = 0;

                try
                {
                    packetPtr = WintunNative.WintunReceivePacket(_session, out packetSize);

                    if (packetPtr == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();

                        if (err == ERROR_NO_MORE_ITEMS)
                        {
                            int signaled = WaitHandle.WaitAny(new WaitHandle[] { readEvent, ct.WaitHandle });
                            if (signaled == 1)
                                ct.ThrowIfCancellationRequested();

                            continue;
                        }

                        if (err == ERROR_HANDLE_EOF)
                            yield break;

                        if (err == ERROR_INVALID_DATA)
                            throw new InvalidOperationException("Wintun receive buffer is corrupt.");

                        throw new Win32Exception(err);
                    }

                    byte[] managedPacket = new byte[packetSize];
                    Marshal.Copy(packetPtr, managedPacket, 0, (int)packetSize);
                    yield return managedPacket;
                }
                finally
                {
                    if (packetPtr != IntPtr.Zero)
                        WintunNative.WintunReleaseReceivePacket(_session, packetPtr);
                }
            }
        }

        public ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct)
        {
            if (_session == IntPtr.Zero)
                throw new InvalidOperationException("Wintun session is not started. Call StartAsync first.");

            ct.ThrowIfCancellationRequested();

            if (packet.Length == 0)
                return ValueTask.CompletedTask;

            // 1) Allocate space in Wintun send ring buffer
            IntPtr sendPtr = WintunNative.WintunAllocateSendPacket(_session, (uint)packet.Length);

            if (sendPtr == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"WintunAllocateSendPacket failed. Win32 error: {err}");
            }

            // 2) Copy managed packet into native buffer
            byte[] temp = packet.ToArray(); // simple + safe
            Marshal.Copy(temp, 0, sendPtr, temp.Length);

            // 3) Send packet to OS
            WintunNative.WintunSendPacket(_session, sendPtr);

            return ValueTask.CompletedTask;
        }

        public ValueTask StopAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            // End the active Wintun session first.
            if (_session != IntPtr.Zero)
            {
                WintunNative.WintunEndSession(_session);
                _session = IntPtr.Zero;
            }

            // The read event belongs to the session lifecycle,
            // so just clear the field after ending the session.
            _readEvent = IntPtr.Zero;

            // Then close the adapter itself.
            if (_adapter != IntPtr.Zero)
            {
                WintunNative.WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
            }

            return ValueTask.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await StopAsync(CancellationToken.None);
            }
            catch
            {
                // Ignore cleanup exceptions during disposal.
            }

            // Final safety reset.
            _readEvent = IntPtr.Zero;
            _session = IntPtr.Zero;
            _adapter = IntPtr.Zero;
        }
        private static (string Ip, int PrefixLength) ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new InvalidOperationException($"Invalid CIDR: {cidr}");

            return (parts[0], int.Parse(parts[1]));
        }

        private static string _Escape(string value) => $"\"{value}\"";
        private async Task<string[]> GetNonTunnelAdapterAliasesAsync(CancellationToken ct)
        {
            string adapterName = _config.AdapterName.Replace("'", "''");

            string output = await RunPowerShellCaptureAsync(
                $"Get-NetAdapter | Where-Object {{$_.Status -eq 'Up' -and $_.Name -ne '{adapterName}'}} | Select-Object -ExpandProperty Name",
                ct);

            return output
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        private static async Task<string> RunPowerShellCaptureAsync(string command, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start PowerShell.");

            string stdout = await process.StandardOutput.ReadToEndAsync(ct);
            string stderr = await process.StandardError.ReadToEndAsync(ct);

            await process.WaitForExitAsync(ct);

            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"Command failed.\n{command}\nSTDOUT: {stdout}\nSTDERR: {stderr}");

            return stdout;
        }
        private static async Task RunPowerShellAsync(string command, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start PowerShell.");

            string stdout = await process.StandardOutput.ReadToEndAsync(ct);
            string stderr = await process.StandardError.ReadToEndAsync(ct);

            await process.WaitForExitAsync(ct);

            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"Command failed.\n{command}\nSTDOUT: {stdout}\nSTDERR: {stderr}");
        }
    }
}
