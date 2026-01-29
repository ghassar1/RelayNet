using RelayNet.Core.Models;
using System.Text.Json;

namespace RelayNet.Directory.Services
{
    public static class RelayListBuilder
    {
        public static byte[] BuildPayloadBytes(RelayListPayload payload)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = false
            };

            return JsonSerializer.SerializeToUtf8Bytes(payload, options);
        }
    }
}
