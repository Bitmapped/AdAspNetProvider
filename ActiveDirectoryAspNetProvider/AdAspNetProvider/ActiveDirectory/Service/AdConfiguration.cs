using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Net;

namespace AdAspNetProvider.ActiveDirectory.Service
{
    public class AdConfiguration
    {
        #region Constructor
        /// <summary>
        /// Constructor to define default values.
        /// </summary>
        public AdConfiguration()
        {
            // Specify domain as default context type.
            this.ContextType = ContextType.Domain;

            // Specify default context options.  Negotiate, signing, and sealing are default used by PrincipalContext.
            this.ContextOptions = ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing;

            // Specify default identity type.
            this.IdentityType = IdentityType.SamAccountName;

            // Specify default maximum number of attempts.
            this.MaxAttempts = 50;

            // Specify maximum number of times server can fail.
            this.MaxServerFailures = 3;

            // Specify default cache duration in minutes.
            this.CacheDurationInMinutes = 30;

            // Default to empty list.
            this.IgnoreServerIpAddresses = new List<IPAddress>();
        }
        #endregion

        #region Properties
        /// <summary>
        /// Context type for connection.
        /// </summary>
        [System.ComponentModel.DefaultValue(ContextType.Domain)]
        public ContextType ContextType { get; set; }

        /// <summary>
        /// Define context options.
        /// </summary>
        [System.ComponentModel.DefaultValue(ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing)]
        public ContextOptions ContextOptions { get; set; }

        /// <summary>
        /// AD server name.
        /// </summary>
        public string Server { get; set; }

        /// <summary>
        /// Container to restrict search path.
        /// </summary>
        public string Container { get; set; }

        /// <summary>
        /// Username for connection.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Password for connection.
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Identity type to search.
        /// </summary>
        [System.ComponentModel.DefaultValue(IdentityType.SamAccountName)]
        public IdentityType IdentityType { get; set; }

        /// <summary>
        /// Maximum number of times to attempt operation before failing.
        /// </summary>
        [System.ComponentModel.DefaultValue(50)]
        public int MaxAttempts { get; set; }

        /// <summary>
        /// Maximum number of times server can fail before it is ignored.
        /// </summary>
        [System.ComponentModel.DefaultValue(3)]
        public int MaxServerFailures { get; set; }

        /// <summary>
        /// Duration of cache (in minutes)
        /// </summary>
        [System.ComponentModel.DefaultValue(30)]
        public int CacheDurationInMinutes { get; set; }

        /// <summary>
        /// Server IPs to ignore if returned by DNS
        /// </summary>
        public List<IPAddress> IgnoreServerIpAddresses { get; set; }

        #endregion

        /// <summary>
        /// Method to implement ICloneable, duplicate this object.
        /// </summary>
        /// <returns>Memberwise clone.</returns>
        public AdConfiguration Clone()
        {
            return (AdConfiguration)this.MemberwiseClone();
        }
    }
}
