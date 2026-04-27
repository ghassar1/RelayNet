
namespace RelayNet.Core.Networking;
public sealed record InnerFrame(
    uint StreamId,
    byte InnerType,
    byte[] Payload
);
