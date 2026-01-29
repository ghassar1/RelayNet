namespace RelayNet.Core.Models;

public sealed record RelayDescriptor(
    string? RelayId,
    RelayRole Role,
    string Address,
    string? IdentityPublicKey // allowed null/empty for now
);