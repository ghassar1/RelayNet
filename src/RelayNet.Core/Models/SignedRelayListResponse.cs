namespace RelayNet.Core.Models;

public sealed record SignedRelayListResponse(
    string KeyId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string PayloadBase64,
    string SignatureBase64
);