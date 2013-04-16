using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

namespace AdAspNetProvider.ActiveDirectory.Support
{
    internal class DnsCacheItem
    {
        /// <summary>
        /// Constructor to create new DnsCache item.
        /// </summary>
        /// <param name="serverIP">Server IP to store.</param>
        public DnsCacheItem(IPAddress serverIP)
        {
            // Store values.
            this.IpAddress = serverIP;
            this.FailCount = 0;
        }

        /// <summary>
        /// IP address of server.
        /// </summary>
        public IPAddress IpAddress { get; set; }

        /// <summary>
        /// Number of times this server has failed since last refresh.
        /// </summary>
        public int FailCount { get; set; }
    }
}
