using RelayNet.Core.Models;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RelayNet.Client.Services
{
    public sealed class RelayListProcessor
    {
        private readonly RelayListVerifier _verifier;

        public RelayListProcessor(RelayListVerifier verifier) {
            _verifier = verifier;
        }

        public RelayListPayload VerifyParseAndValidate(SignedRelayListResponse resp)
        { 
             // 1) Expiry check basic
             if(DateTimeOffset.UtcNow > resp.ExpiresAt)
                throw new Exception("Relay list response has expired at {resp.ExpireAt:u}.");

             // 2) Signature verify over exact bytes 
             var ok = _verifier.Verify(resp.PayloadBase64, resp.SignatureBase64);
                if(!ok)
                    throw new Exception("Relay list response signature verification failed.");

                // 3) Decode + parse payload (only after verify)
                var payloadBytes = Convert.FromBase64String(resp.PayloadBase64);
                var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            var payload = JsonSerializer.Deserialize<RelayListPayload>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) 
                ?? throw new Exception("Failed to parse relay list payload JSON."); ;

            Validate(payload);
                return payload;

        }

        private static void Validate(RelayListPayload payload)
        {
            if (payload.Relays is null || payload.Relays.Count != 3)
                throw new Exception("Relay list payload must contain exactly 3 relays.");

            // unique RelayId
            var dup = payload.Relays.GroupBy(r => r.RelayId)
                .FirstOrDefault(g => g.Count() > 1);

            if (dup is not null)
                throw new Exception($"Relay list payload contains duplicate RelayId: {dup.Key}");

            // must have at least one of each role for 3-hop
            if(!payload.Relays.Any(r => r.Role == RelayRole.Entry))
                throw new Exception("No entry relays avaliable");
            if (!payload.Relays.Any(r => r.Role == RelayRole.Middle))
                throw new Exception("No Middle relays avaliable");
            if (!payload.Relays.Any(r => r.Role == RelayRole.Exit))
                throw new Exception("No Exit relays avaliable");

        }

        public (RelayDescriptor entry, RelayDescriptor middle, RelayDescriptor exist) Select3HopRelays(RelayListPayload payload)
        {
            RelayDescriptor Pick(IEnumerable<RelayDescriptor> items)
            { 
                var list = items.ToList();
                var idx = RandomNumberGenerator.GetInt32(list.Count);
                return list[idx];
            }

            var entry = Pick(payload.Relays.Where(r => r.Role == RelayRole.Entry));
            var middle = Pick(payload.Relays.Where(r => r.Role == RelayRole.Middle));
            var exit = Pick(payload.Relays.Where(r => r.Role == RelayRole.Exit));

            // Optional: ensure they're not the same relayId 
            // (useful if you ever allow one relay to advertise multiple roles)
            if (entry.RelayId == middle.RelayId || entry.RelayId == exit.RelayId || middle.RelayId == exit.RelayId)
                throw new Exception("Selected overlapping relays. Try again or eenforce role separation.");

            return (entry, middle, exit);
        }
    }
}
