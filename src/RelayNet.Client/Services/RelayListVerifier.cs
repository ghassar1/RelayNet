using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace RelayNet.Client.Services
{
    public sealed class RelayListVerifier
    {
        private readonly string _publicKeyPemPath; 

        public RelayListVerifier(string publicKeyPemPath) {
            _publicKeyPemPath = publicKeyPemPath;
        }

        public bool Verify(string payloadBase64, string signatureBase64)
        {
            var payloadBytes = Convert.FromBase64String(payloadBase64);
            var signatureBytes = Convert.FromBase64String(signatureBase64);

            var pem = File.ReadAllText(_publicKeyPemPath);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);

            return ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256);

        }
    }
}
