using RelayNet.Client.Services;
using RelayNet.Core.Models;
using RelayNet.Core.Networking;
using RelayNet.Core.Services;
using System.Net.Sockets;   
using System.Reflection;
using System.Text;


//------------------------
// Setup 
//-----------------------

var directoryUrl = "https://localhost:7030/relays";
var publicKeyPath = Path.Combine(AppContext.BaseDirectory, "Keys", "directory_signing_public.pem");

using var httpClient = new HttpClient();


var api = new DirectoryApiClient(httpClient);
var verifier = new RelayListVerifier(publicKeyPath);
var processor = new RelayListProcessor(verifier);

SignedRelayListResponse resp = await api.GetSignedRelayListAsync(directoryUrl, CancellationToken.None);
var payload = processor.VerifyParseAndValidate(resp);
var (entry, middle, exist) = processor.Select3HopRelays(payload);

Console.WriteLine($"Selected path:"); 
Console.WriteLine($" Entry: {entry.RelayId} @ { entry.Address}");
Console.WriteLine($" Middle: {middle.RelayId} @ {middle.Address}");
Console.WriteLine($" Exist: {exist.RelayId} @ {exist.Address}");

//------------------------
// Parse host/port
//-----------------------
var (entryHost, entryPort) = ParseHostPort(entry.Address);


//------------------------
// Create RelayClient for entry
//-----------------------

var entryClient = new RelayClient(entryHost, entryPort);
await entryClient.ConnectAsync();



// TODO: handshake with entry relay using entry.IdentityPublicKey


//------------------------
// Send message
//-----------------------
await entryClient.SendFrameAsync(new Frame(FrameType.Forward, Encoding.UTF8.GetBytes("hello")));
var response = await entryClient.ReceiveFrameAsync();

Console.WriteLine($"Relay: {Encoding.UTF8.GetString(response.Payload)}");


//------------------------
// Dispose at the end
//-----------------------
await entryClient.DisposeAsync();
Console.WriteLine("Connection closed.");
Console.ReadLine();



//------------------------
// Helpers
//-----------------------
static (string host, int port) ParseHostPort(string address)
{
   var parts = address.Split(':');
    if (parts.Length != 2)
         throw new FormatException($"Invalid address format: {address}");
    return (parts[0], int.Parse(parts[1]));
}



























//var directoryUrl = "https://localhost:7030/relays";
//var publicKeyPath = Path.Combine(AppContext.BaseDirectory, "Keys", "directory_signing_public.pem"); 

//using var httpClient = new HttpClient();


//var api = new DirectoryApiClient(httpClient);
//var verifier = new RelayListVerifier(publicKeyPath);
//var processor = new RelayListProcessor(verifier);

//SignedRelayListResponse resp = await api.GetSignedRelayListAsync(directoryUrl, CancellationToken.None);

//Console.WriteLine($"KeyId: {resp.KeyId}");
//Console.WriteLine($"IssuedAt: {resp.IssuedAt:u}");
//Console.WriteLine($"ExpiresAt: {resp.ExpiresAt:u}");

//var payload = processor.VerifyParseAndValidate(resp);

//Console.WriteLine($"Relay count: {payload.Relays.Count}");

//var (entry, middle, exist) = processor.Select3HopRelays(payload);

//Console.WriteLine("Selected path:");
//Console.WriteLine($" Entry: {entry.RelayId} @ {entry.Address}");
//Console.WriteLine($" Middle: {middle.RelayId} @ {middle.Address}");
//Console.WriteLine($" Exit: {exist.RelayId} @ {exist.Address}");
////Console.ReadLine();

//var (entryHost, entryPort) = ParseHostPort(entry.Address);


//var reply = await SendForwardAsync(entryHost, entryPort, "hello");

//Console.WriteLine($"Replay: {reply}");

//Console.ReadLine();

////var (entryHost, entryPort) = ParseHostPort(entry.Address);

////Console.WriteLine($"Pinging entry relay at {entryHost}:{entryPort}...");


////var pong = await PingRelayAsync(entryHost, entryPort);

////Console.WriteLine($"Entry relay responded: {pong}");

////Console.ReadLine();

//static (string host, int port) ParseHostPort(string address)
//{
//   var parts = address.Split(':');
//    if (parts.Length != 2)
//         throw new FormatException($"Invalid address format: {address}");
//    return (parts[0], int.Parse(parts[1]));
//}

//static async Task<bool> PingRelayAsync(string host, int port)
//{
//    using var client = new TcpClient();
//    await client.ConnectAsync(host, port);


//    using var stream = client.GetStream();

//    await FrameCodec.WriteAsync(stream, new Frame(FrameType.Ping, Array.Empty<byte>()), CancellationToken.None);


//    var response = await FrameCodec.ReadAsync(stream, CancellationToken.None);
//    return response.Type == FrameType.Pong;
//}

//static async Task<string> SendForwardAsync(string host, int port, string message)
//{ 

//    await using var conn = await RelayConnection.ConnectAsync(host, port);

//    await FrameCodec.WriteAsync(conn.Stream, new Frame(FrameType.Forward, Encoding.UTF8.GetBytes(message)), CancellationToken.None);

//    var response = await FrameCodec.ReadAsync(conn.Stream, CancellationToken.None);

//    return $"{response.Type} : {Encoding.UTF8.GetString(response.Payload)}";

//}

