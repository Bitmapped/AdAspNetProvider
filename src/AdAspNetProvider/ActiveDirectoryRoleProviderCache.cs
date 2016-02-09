using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AdAspNetProvider
{
    public class ActiveDirectoryRoleProviderCache
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="roles">Roles to store in cache.</param>
        public ActiveDirectoryRoleProviderCache(string[] roles)
        {
            this.Roles = roles;
        }

        /// <summary>
        /// Role names
        /// </summary>
        public string[] Roles { get; set; }
    }
}
