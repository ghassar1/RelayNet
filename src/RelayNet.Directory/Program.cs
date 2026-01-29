using RelayNet.Core.Models;
using RelayNet.Directory.Services;


var builder = WebApplication.CreateBuilder(args);

// Read config for signing
var KeyId = builder.Configuration["DirectorySigning:KryId"] ?? "dir-signing-001";
var privateKeyPath = builder.Configuration["DirectorySigning:PrivateKeyPath"] 
    ?? throw new InvalidOperationException("Missing DirectorySigning:PrivateKeyPath in config");

// Register signing service
builder.Services.AddSingleton(new DirectorySigningService(privateKeyPath));
var app = builder.Build();


app.MapGet("/relays", (DirectorySigningService signer) => {

    var loader = new RelayPublicKeyLoader(@"C:\RelayNetPublicKeys");
    var keys = loader.LoadRelayKeys();


    // Map role name to IP:port 
    string GetAddress(string roleName) => roleName.ToLower() switch
    {
        "entry" => "127.0.0.1:9002",
        "middle" => "127.0.0.1:9003",
        "exit" => "127.0.0.1:9004",
        _ => throw new InvalidOperationException()
    };

    var descriptors = RelayDescriptorFractory.CreateDescriptors(keys, GetAddress);

    var payload = new RelayListPayload(
        Version: 1,
        Relays: descriptors
        );

    var payloadBytes = RelayListBuilder.BuildPayloadBytes(payload);
    var signatureBytes = signer.SignData(payloadBytes);

    var response = new SignedRelayListResponse(
        KeyId: KeyId,
        IssuedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(24),
        PayloadBase64: Convert.ToBase64String(payloadBytes),
        SignatureBase64: Convert.ToBase64String(signatureBytes)
        );

    return Results.Json(response);
    //var payload = new RelayListPayload(
    //    Version: 1, 
    //    Relays: new List<RelayDescriptor>
    //    { 
    //        new("relay-001", RelayRole.Entry, "127.0.0.1:9002", IdentityPublicKey: null), 
    //        new("relay-003", RelayRole.Middle, "127.0.0.1:9003", IdentityPublicKey: null),
    //        new("relay-002", RelayRole.Exit, "127.0.0.1:9004", IdentityPublicKey: null)
    //    }
    //    );

    //// serialize to exact byte
    //var payloadBytes = RelayListBuilder.BuildPayloadBytes(payload);


    //// sign exact byte
    //var signatureBytes = signer.SignData(payloadBytes);

    ////Wrap response

    //var issuedAt = DateTimeOffset.UtcNow; 
    //var expiresAt = issuedAt.AddHours(24);

    //var response = new SignedRelayListResponse(
    //    KeyId: KeyId,
    //    IssuedAt: issuedAt,
    //    ExpiresAt: expiresAt,
    //    PayloadBase64: Convert.ToBase64String(payloadBytes),
    //    SignatureBase64: Convert.ToBase64String(signatureBytes)
    //    );

    //return Results.Json(response);
});

app.Run();
