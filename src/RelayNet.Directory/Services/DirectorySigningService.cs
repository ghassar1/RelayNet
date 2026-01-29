using System.Security.Cryptography;

namespace RelayNet.Directory.Services
{
    public class DirectorySigningService
    {
        private readonly ECDsa _ecdsa; 

        public DirectorySigningService(string privateKeyPemPath) {
            if (!File.Exists(privateKeyPemPath))
                throw new FileNotFoundException("Directory signing private key not found.", privateKeyPemPath);
            
            var pem = File.ReadAllText(privateKeyPemPath);

            _ecdsa = ECDsa.Create();
            _ecdsa.ImportFromPem(pem);

        }

        public byte[] SignData(byte[] data)
        {
            return _ecdsa.SignData(data, HashAlgorithmName.SHA256);
        }
    }
}
