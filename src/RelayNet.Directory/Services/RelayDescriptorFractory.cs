using RelayNet.Core.Models;


namespace RelayNet.Directory.Services
{
    public class RelayDescriptorFractory
    {
        /// <summary>
        /// Builds RelayDescriptor list from RelayKeyInfo list + optional IP mapping.
        /// </summary>
        /// 
        public static List<RelayDescriptor> CreateDescriptors(List<RelayKeyInfo> keys,
            Func<string, string> getAddressForRole) { 
        if (keys == null) throw new ArgumentNullException(nameof(keys));
        if (getAddressForRole == null) throw new ArgumentNullException(nameof(getAddressForRole));

        return keys.Select(k => new RelayDescriptor(
            k.RelayId!, 
            Role: Enum.Parse<RelayRole>(k.RoleName, ignoreCase: true),
            Address: getAddressForRole(k.RoleName),
            IdentityPublicKey: Convert.ToBase64String(k.PublicKey)
            )).ToList();
        }
    }
}
