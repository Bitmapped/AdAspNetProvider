using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

namespace AdAspNetProvider.ActiveDirectory.Support
{
    public class AdConfiguration
    {
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
        }

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
        /// Method to implement ICloneable, duplicate this object.
        /// </summary>
        /// <returns>Memberwise clone.</returns>
        public AdConfiguration Clone()
        {
            return (AdConfiguration)this.MemberwiseClone();
        }
    }
}
