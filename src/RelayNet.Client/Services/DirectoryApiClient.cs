using RelayNet.Core.Models;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace RelayNet.Client.Services
{
    public sealed class DirectoryApiClient
    {
        private readonly  HttpClient _http;

        public DirectoryApiClient(HttpClient http)
        {
            _http = http;
        }

        public async Task<SignedRelayListResponse> GetSignedRelayListAsync(string url, CancellationToken ct)
        {
            using var res = await _http.GetAsync(url, ct);
            res.EnsureSuccessStatusCode();

            var json = await res.Content.ReadAsStringAsync(ct);

            var obj = JsonSerializer.Deserialize<SignedRelayListResponse>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );

            return obj ?? throw new Exception($"Failed to parse response: {json}");
        }
    }
}
