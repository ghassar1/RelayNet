using RelayNet.Core.Networking;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.Marshalling;
using System.Security.Cryptography;
using System.Text;

namespace RelayNet.Core.Services
{

    // TODO: Add timeouts, retries, better error handling, logging etc.
    // TODO: Add replay protection, SecureData framing, Onion layers, Unit tests, Directory trust model
    //Lock framing spec permanently
    public class HandshakeService
    {
        /// <summary>
        /// Performs challenge-response and establishes ECDH session key. 
        /// </summary>
        /// <param name="clien">Connected RelayClient</param>
        /// <param name="relayPublicKeyBytes">Relay's public key (from directory)</param>
        /// <param name="ct"></param>
        /// <returns>Shared session key (byte[32])</returns>
        /// 
        /// <summary>
        /// Client side handshake with handshake enforcement and session tracking.
        /// </summary>
        public static async Task<RelaySession> PerformHandshakeAsync(
            RelayConnection conn, 
            byte[] relayPublicKeyBytes, 
            CancellationToken ct = default)
            {

            if (conn.Session?.State == ConnectionState.HandshakeComplete)
                throw new InvalidOperationException("Handshake already completed on this connection.");

            var session = new RelaySession();

            // Generate client ephemeral key (ECDH P-256)
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var clientPubKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
            session.ClientEphemeralPublicKey = clientPubKey;

            //Send client's ehemeral public key to relay as handshake
            await conn.SendFrameAsync(new Frame(FrameType.Handshake, clientPubKey), ct);

            // Receive relay's challenge (relay signs a random challange)
            var challengeFrame = await conn.ReceiveFrameAsync(ct);
            if (challengeFrame.Type != FrameType.Challenge)
                throw new Exception("Expected Challenge frame from relay");

            var challengePayload = challengeFrame.Payload; // [signature + random bytes]

            // Assume first 64 byte = siganture, rest = challenge bytes
            var signature = challengePayload[..64];
            var challenge = challengePayload[64..];

            session.Challenge = challenge;
            session.ChallengeSignature = signature; 

            // Verify relay's signature on the challenge
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(relayPublicKeyBytes, out _);
            if(!ecdsa.VerifyData(challenge, signature, HashAlgorithmName.SHA256))
                throw new Exception("Relay signature verification failed.");

            // Respond with signed challenge
            // In this simple version we just send the raw challange encrypted with client's private key 
            await conn.SendFrameAsync(new Frame(FrameType.ChallengeResponse, challenge), ct);


            // Receive relay's ephemeral public key for ECDH 
            var relayKeyFrame = await conn.ReceiveFrameAsync(ct);
            if (relayKeyFrame.Type != FrameType.Handshake)
                throw new Exception("Expected Handshake frame from relay with its public key.");

            var relayPubKey = relayKeyFrame.Payload;
            using var relayEcdhPub = ECDiffieHellman.Create();
            relayEcdhPub.ImportSubjectPublicKeyInfo(relayPubKey, out _);
            session.RelayEphemeralPublicKey =  relayPubKey;

            // Derive shared session key
            session.SessionKey = ecdh.DeriveKeyFromHash(relayEcdhPub.PublicKey, HashAlgorithmName.SHA256);
            session.State = ConnectionState.HandshakeComplete;

            conn.Session = session;

            return session;
        }

        //Relay / Responder side handshake with challenege + state enforcement
        public static async Task<RelaySession> RespondToHandshakeAsync(
            RelayConnection conn, byte[] relayIdentityPrivateKey, 
            CancellationToken ct = default)
        {

            if (conn.Session?.State == ConnectionState.HandshakeComplete)
                throw new InvalidOperationException("Handshake already completed on this connection.");

            var session = new RelaySession();

            // Receive client ephemeral key
            var clientFrame = await conn.ReceiveFrameAsync(ct);
            if (clientFrame.Type != FrameType.Handshake)
                throw new Exception("Expected handshake frame from client");

            var clientEcdhPubBytes = clientFrame.Payload;
            session.ClientEphemeralPublicKey = clientEcdhPubBytes;

            //Generate relay ephemeral key 
            using var relayEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var relayPubKey = relayEcdh.PublicKey.ExportSubjectPublicKeyInfo();
            session.RelayEphemeralPublicKey = relayPubKey;

            // Create random challenge 
            var challenge = RandomNumberGenerator.GetBytes(32);

            // Sign challenge with relay identity private key 
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(relayIdentityPrivateKey, out _);
            var signature = ecdsa.SignData(challenge, HashAlgorithmName.SHA256);
            var challengePayload = signature.Concat(challenge).ToArray();


            session.Challenge = challenge;
            session.ChallengeSignature = signature;


            // Send challenge frame
            await conn.SendFrameAsync(new Frame(FrameType.Challenge, challengePayload), ct); 

            // Receive client response
            var responseFrame = await conn.ReceiveFrameAsync(ct);
            if (responseFrame.Type != FrameType.ChallengeResponse)
                throw new Exception("Expected ChallengeResponse frame from client.");


            if(!responseFrame.Payload.SequenceEqual(challenge))
                throw new Exception("Client failed to respond correctly to challenge.");

            // Send relat ephemeral key
            await conn.SendFrameAsync(new Frame(FrameType.Handshake, relayPubKey), ct);

            // Derive session key
            using var clientEcdhPub = ECDiffieHellman.Create();
            clientEcdhPub.ImportSubjectPublicKeyInfo(clientEcdhPubBytes, out _);
            session.SessionKey = relayEcdh.DeriveKeyFromHash(clientEcdhPub.PublicKey, HashAlgorithmName.SHA256);
            session.State = ConnectionState.HandshakeComplete;

            conn.Session = session;

            return session;

        }

    }
}
