namespace RelayNet.Core.Networking;

public sealed record Frame(FrameType Type, byte[] Payload);