using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace AdAspNetProvider.ActiveDirectory.Support
{
    static public class Dns
    {

        // Define cache for storing variables.
        static private Dictionary<string, IPAddress[]> ipCache = new Dictionary<string, IPAddress[]>();

        /// <summary>
        /// Get IP addresses for the specified DNS host or IP address.
        /// </summary>
        /// <param name="host">Host to lookup.</param>
        /// <returns>IP addresses for host.</returns>
        static public IPAddress[] GetIpAddresses(string host)
        {
            // See if IP addresses are cached.
            if (Dns.ipCache.ContainsKey(host) && Dns.ipCache[host].Any())
            {
                return Dns.ipCache[host];
            }

            // Values are not cached.  Load them up.
            var ipAddresses = System.Net.Dns.GetHostAddresses(host);

            // Store values in cache.
            Dns.ipCache.Remove(host);
            Dns.ipCache.Add(host, ipAddresses);

            // Get host entry.
            return ipAddresses;
        }
    }
}
