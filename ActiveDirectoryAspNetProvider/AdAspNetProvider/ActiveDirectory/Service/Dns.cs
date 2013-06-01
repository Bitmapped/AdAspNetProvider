using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;

namespace AdAspNetProvider.ActiveDirectory.Service
{
    public class Dns
    {
        #region Constructor
        /// <summary>
        /// Constructor.
        /// </summary>
        public Dns(AdConfiguration config)
        {
            // Initialize DnsCache.
            this.DnsCache = new ConcurrentDictionary<string, DnsCache>();

            // Store configuration.
            this.Config = config;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Cache for storing Dns entries.
        /// </summary>
        private ConcurrentDictionary<string, DnsCache> DnsCache { get; set; }

        /// <summary>
        /// Stores configuration settings.
        /// </summary>
        private AdConfiguration Config { get; set; }
        #endregion

        /// <summary>
        /// Get IP addresses for the specified DNS host or IP address.
        /// </summary>
        /// <param name="host">Host to lookup.</param>
        /// <returns>IP addresses for host.</returns>
        public IPAddress[] GetIpAddresses(string host)
        {
            // Load DNS entries into cache if needed.
            this.DnsCache.TryAdd(host, new DnsCache(host, this.Config));

            // Get Ip addresses from cache.
            return this.DnsCache[host].GetIpAddresses();
        }

        /// <summary>
        /// Gets next server IP to try.
        /// </summary>
        /// <param name="host">Hostname to use.</param>
        /// <param name="attempt">Attempt number (for sequential selection of IPs) or null for random selection.</param>
        /// <returns>Next server IP to use.</returns>
        public IPAddress GetIpAddress(string host, int? attempt = null)
        {
            // Get server IPs.
            var serverIPs = this.GetIpAddresses(host);

            // Determine which server to try.  If attempt number is specified, work through returned IPs in order.  Otherwise, select random.
            IPAddress serverIP = null;
            if (attempt == null)
            {
                // Get random number.
                var random = new Random();

                serverIP = serverIPs[random.Next(serverIPs.Count())];
            }
            else
            {
                serverIP = serverIPs[attempt.Value % serverIPs.Count()];
            }

            return serverIP;
        }

        /// <summary>
        /// Records failure with specified server IP.
        /// </summary>
        /// <param name="host">Hostname being used.</param>
        /// <param name="serverIP">IP address that failed.</param>
        public void RecordFailure(string host, IPAddress serverIP)
        {
            // Ensure host is valid.
            if (this.DnsCache.ContainsKey(host))
            {
                // Record failure on host.
                this.DnsCache[host].RecordFailure(serverIP);
            }
        }
    }
}
