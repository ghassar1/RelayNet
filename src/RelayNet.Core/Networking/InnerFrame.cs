
namespace RelayNet.Core.Networking;
public sealed record InnerFrame(
    byte InnerType,
    byte[] Payload
);
