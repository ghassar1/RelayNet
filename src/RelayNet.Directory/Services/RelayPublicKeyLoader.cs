
using System.Security.Cryptography;

namespace RelayNet.Directory.Services
{
    /// <summary>
    /// Reads public keys from disk and computes RelaId for each relay. 
    /// Returns a list of simple RelayKeyInfo objects.
    /// </summary>
    public class RelayPublicKeyLoader
    {
        private readonly string _publicKeysFolder;

        public RelayPublicKeyLoader(string publicKeysFolder)
        {
            if (!System.IO.Directory.Exists(publicKeysFolder))
                throw new DirectoryNotFoundException($"Public keys folder not found: {publicKeysFolder}");
            _publicKeysFolder = publicKeysFolder;
        }
        public List<RelayKeyInfo> LoadRelayKeys()
        {
            var result = new List<RelayKeyInfo>();

            // Assume filenames like entry_publkic.bin, middle_public.bin, exit_public.bin

            foreach (var file in System.IO.Directory.GetFiles(_publicKeysFolder, "*_public.bin"))
            { 
                var bytes = System.IO.File.ReadAllBytes(file);

                //Role is derived from filename
                string fileName = System.IO.Path.GetFileNameWithoutExtension(file);
                string roleName = fileName.Split('_')[0]; // "entry", "middle", "exit"

                // Compute relayId = SHA256(publicKey)
                using var sha = SHA256.Create();
                byte[] hashBytes = sha.ComputeHash(bytes);
                string relayId = Convert.ToHexString(hashBytes);

                result.Add(new RelayKeyInfo
                {
                    PublicKey = bytes,
                    RoleName = roleName,
                    RelayId = relayId
                });


            }
            return result;
        }

    }
    public class RelayKeyInfo
    {
        public byte[] PublicKey { get; init; }
        public string RoleName { get; init; }
        public string RelayId { get; init; }

    }
}
