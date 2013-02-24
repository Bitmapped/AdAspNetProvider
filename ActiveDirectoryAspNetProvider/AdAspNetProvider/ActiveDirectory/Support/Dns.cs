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
        /// <summary>
        /// Get IP addresses for the specified DNS host or IP address.
        /// </summary>
        /// <param name="host">Host to lookup.</param>
        /// <returns>IP addresses for host.</returns>
        static public IEnumerable<IPAddress> GetIpAddresses(string host)
        {
            // Get host entry.
            return System.Net.Dns.GetHostAddresses(host).AsEnumerable();
        }
    }
}
