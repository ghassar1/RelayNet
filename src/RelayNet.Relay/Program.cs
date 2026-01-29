
using RelayNet.Relay;


var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<RelayOptions>(builder.Configuration.GetSection("Relay"));
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
