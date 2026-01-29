using Microsoft.Extensions.Options;
using RelayNet.Core.Networking;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RelayNet.Relay;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly RelayOptions _opts;


    public Worker(ILogger<Worker> logger, IOptions<RelayOptions> options)
    {
        _logger = logger;
        _opts = options.Value;
    }

    private static (string host, int port) ParseHostPort(string s)
    { 
        var parts = s.Split(':',2);
        if (parts.Length != 2) throw new FormatException($"Invalid NextHop: {s}");
        return (parts[0], int.Parse(parts[1]));
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {

        var ip = IPAddress.Parse(_opts.ListenAddress);
        var listener = new TcpListener(ip, _opts.ListenPort);

        listener.Start();
        _logger.LogInformation("Relay ({Role}) listening on {Addr}:{Port}", _opts.Role, _opts.ListenAddress, _opts.ListenPort);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stoppingToken);
                _ = HandleClientAsync(client, stoppingToken);

            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
            _logger.LogInformation("Relay stopped.");
        }
    }
    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        using var stream = client.GetStream();

        _logger.LogInformation("Client connected: {Remote}", client.Client.RemoteEndPoint);


        while (!ct.IsCancellationRequested)
        {
            Frame frame;
            try
            {
                frame = await FrameCodec.ReadAsync(stream, ct);
            }
            catch (Exception ex)
            {
                _logger.LogInformation(ex, "Client disconnected.");
                break;
            }

            _logger.LogInformation("Received frame: {Type}", frame.Type);

            if (frame.Type == FrameType.Ping)
            {
                var pong = new Frame(FrameType.Pong, Array.Empty<byte>());
                await FrameCodec.WriteAsync(stream, pong, ct);
                _logger.LogInformation("Sent Pong.");
            }
            else if (frame.Type == FrameType.Forward)
            {
                if (string.Equals(_opts.Role, "Exit", StringComparison.OrdinalIgnoreCase))
                { 
                    var msg = Encoding.UTF8.GetString(frame.Payload);
                    _logger.LogInformation("Exit received FORWWARD payload: {Msg}", msg);

                    var relay = new Frame(FrameType.EchoReplay, frame.Payload);
                    await FrameCodec.WriteAsync(stream, relay, ct);
                    _logger.LogInformation("Exit send EchoReplay back.");
                    continue;
                }

                if (string.IsNullOrEmpty(_opts.NextHop))
                { 
                    _logger.LogWarning("No NextHop configured, cannot forward.");
                    continue;
                }

                var (nextHost, nextPort) = ParseHostPort(_opts.NextHop);

                using var nextClient = new TcpClient();
                await nextClient.ConnectAsync(nextHost, nextPort, ct);
                using var nextStream = nextClient.GetStream();

                await FrameCodec.WriteAsync(nextStream, frame, ct);
                _logger.LogInformation("{Role} forwarded to {NextHop}", _opts.Role, _opts.NextHop);

                var nextResp = await FrameCodec.ReadAsync(nextStream, ct);
                await FrameCodec.WriteAsync(stream, nextResp, ct);
                _logger.LogInformation("{Role} sent response back: {Type}.", _opts.Role, nextResp.Type);
            }
            else
            {
                // for now, ignoire other frames
            }
        }
    }
}
