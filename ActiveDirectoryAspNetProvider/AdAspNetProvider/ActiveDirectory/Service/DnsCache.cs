using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;

namespace AdAspNetProvider.ActiveDirectory.Service
{
    internal class DnsCache
    {
        #region Constructor
        /// <summary>
        /// Constructor to create cache.
        /// </summary>
        /// <param name="hostname">Hostname associated with cache entries.</param>
        /// <param name="serverIPs"></param>
        public DnsCache(string hostname, AdConfiguration config)
        {
            // Store hostname.
            this.Hostname = hostname;

            // Store configuration.
            this.Config = config;

            // Populate cache.
            this.PopulateCache();            
        }
        #endregion

        #region Properties
        /// <summary>
        /// Stores configuration settings.
        /// </summary>
        private AdConfiguration Config { get; set; }

        /// <summary>
        /// Tracks time DNS entries were last refreshed.
        /// </summary>
        private DateTime CacheLastRefresh { get; set; }

        /// <summary>
        /// Access items in cache.
        /// </summary>
        private ConcurrentDictionary<IPAddress, DnsCacheItem> CacheItems { get; set; }

        /// <summary>
        /// Hostname associated with these cache entries.
        /// </summary>
        private string Hostname { get; set; }
        #endregion

        #region Variables
        private Object lockCacheItems = new Object();
        #endregion

        /// <summary>
        /// Record failure on a server IP.
        /// </summary>
        /// <param name="serverIP">Server IP that experienced failure.</param>
        public void RecordFailure(IPAddress serverIP)
        {
            // Lock cache items to avoid problems with deletes.
            lock (this.lockCacheItems)
            {
                // Check to see if item still exists in cache.
                if (this.CacheItems.ContainsKey(serverIP))
                {
                    // Increment failure.
                    this.CacheItems[serverIP].FailCount++;

                    // If fail count has reached limit, remove entry.
                    if (this.CacheItems[serverIP].FailCount >= this.Config.MaxServerFailures)
                    {
                        DnsCacheItem failedCache;
                        this.CacheItems.TryRemove(serverIP, out failedCache);
                    }
                }
            }
        }

        /// <summary>
        /// Gets array of valid IP addresses for hostname.
        /// </summary>
        /// <returns>Array of IP addresses.</returns>
        public IPAddress[] GetIpAddresses()
        {
            // Check cache is still valid.
            this.CheckCache();

            // Iterate through each server IP.
            var serverIPs = this.CacheItems.Select(c => c.Value.IpAddress);

            return serverIPs.ToArray();
        }

        #region Support methods
        /// <summary>
        /// Perform Dns lookup and populate cache.
        /// </summary>
        private void PopulateCache()
        {
            // Fetch Dns entries to populate cache.
            if (String.IsNullOrWhiteSpace(this.Hostname))
            {
                throw new InvalidOperationException("Hostname not specified.");
            }

            // Store time of last refresh.
            this.CacheLastRefresh = DateTime.Now;

            // Initialize cache.
            this.CacheItems = new ConcurrentDictionary<IPAddress, DnsCacheItem>();

            // Perform Dns lookup.
            var serverIPs = System.Net.Dns.GetHostAddresses(this.Hostname);

            // Store each server IP.
            foreach (var serverIP in serverIPs)
            {
                this.CacheItems.TryAdd(serverIP, new DnsCacheItem(serverIP));
            }

            // If cache is empty, throw error.
            if (!this.CacheItems.Any())
            {
                throw new InvalidOperationException("No IP entries for specified hostname.");
            }
        }

        /// <summary>
        /// Check to see if cache is still valid.  If it is not, repopulate it.
        /// </summary>
        private void CheckCache()
        {
            // Check to ensure cache has not expired and is not empty.
            if (!this.CacheItems.Any() || ((DateTime.Now - this.CacheLastRefresh) >= new TimeSpan(0, this.Config.CacheDurationInMinutes, 0)))
            {
                // Cache is too old.  Refresh it.
                this.PopulateCache();

                // Update refresh timestamp.
                this.CacheLastRefresh = DateTime.Now;
            }
        }
        #endregion
    }
}
