namespace RelayNet.Core.Models;

public sealed record RelayListPayload(
    int Version,
    List<RelayDescriptor> Relays
);