using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Web.Security;

namespace ActiveDirectoryAspNetProvider
{
    internal class ActiveDirectorySessionCache
    {
        public string Username { get; set; }
        public List<string> Roles { get; set; }
        public MembershipUser User { get; set; }

        public ActiveDirectorySessionCache()
        {
            // Initialize roles as null.
            this.Roles = null;
        }
    }
}
