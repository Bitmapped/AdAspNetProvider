using System.Collections.Concurrent;
using System.Collections.Generic;

namespace AdAspNetProvider.ActiveDirectory
{
    public class AdConfiguration : AdAspNetProvider.ActiveDirectory.Service.AdConfiguration
    {
        #region Constructor
        /// <summary>
        /// Constructor to define default values.
        /// </summary>
        public AdConfiguration() : base()
        {
            // Default groups to ignore.
            this.GroupsToIgnore = new List<string>(new string[] {"Domain Guests", "Domain Computers", "Group Policy Creator Owners", "Guests", "Users",
                "Domain Users", "Pre-Windows 2000 Compatible Access", "Exchange Domain Servers", "Schema Admins",
                "Enterprise Admins", "Domain Admins", "Cert Publishers", "Backup Operators", "Account Operators",
                "Server Operators", "Print Operators", "Replicator", "Domain Controllers", "WINS Users",
                "DnsAdmins", "DnsUpdateProxy", "DHCP Users", "DHCP Administrators", "Exchange Services",
                "Exchange Enterprise Servers", "Remote Desktop Users", "Network Configuration Operators",
                "Incoming Forest Trust Builders", "Performance Monitor Users", "Performance Log Users",
                "Windows Authorization Access Group", "Terminal Server License Servers", "Distributed COM Users",
                "Administrators", "Everybody", "RAS and IAS Servers", "MTS Trusted Impersonators",
                "MTS Impersonators", "Everyone", "LOCAL", "Authenticated Users"});

            // Default users to ignore.
            this.UsersToIgnore = new List<string>(new string[] { "Administrator", "TsInternetUser", "Guest", "krbtgt", "Replicate", "SERVICE", "SMSService" });

            // Initialize containers.
            this.AllowedUsers = new List<string>();
            this.AllowedGroups = new List<string>();
            this.GroupsToRename = new ConcurrentDictionary<string, string>();

            // Search recursively by default.
            this.RecursiveGroupMembership = true;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Users to ignore in results.
        /// </summary>
        public List<string> UsersToIgnore { get; set; }

        /// <summary>
        /// Groups to ignore in results.
        /// </summary>
        [System.ComponentModel.DefaultValue(new string[] {"Domain Guests", "Domain Computers", "Group Policy Creator Owners", "Guests", "Users",
                "Domain Users", "Pre-Windows 2000 Compatible Access", "Exchange Domain Servers", "Schema Admins",
                "Enterprise Admins", "Domain Admins", "Cert Publishers", "Backup Operators", "Account Operators",
                "Server Operators", "Print Operators", "Replicator", "Domain Controllers", "WINS Users",
                "DnsAdmins", "DnsUpdateProxy", "DHCP Users", "DHCP Administrators", "Exchange Services",
                "Exchange Enterprise Servers", "Remote Desktop Users", "Network Configuration Operators",
                "Incoming Forest Trust Builders", "Performance Monitor Users", "Performance Log Users",
                "Windows Authorization Access Group", "Terminal Server License Servers", "Distributed COM Users",
                "Administrators", "Everybody", "RAS and IAS Servers", "MTS Trusted Impersonators",
                "MTS Impersonators", "Everyone", "LOCAL", "Authenticated Users"})]
        public List<string> GroupsToIgnore { get; set; }

        /// <summary>
        /// If specified, only return these users in results.
        /// </summary>
        [System.ComponentModel.DefaultValue(new string[] { "Administrator", "TsInternetUser", "Guest", "krbtgt", "Replicate", "SERVICE", "SMSService"})]
        public List<string> AllowedUsers { get; set; }

        /// <summary>
        /// If specified, only return these groups in results.
        /// </summary>
        public List<string> AllowedGroups { get; set; }

        /// <summary>
        /// Groups to be renamed with oldname, newname.
        /// </summary>
        public ConcurrentDictionary<string, string> GroupsToRename { get; set; }

        /// <summary>
        /// Use recursive membership
        /// </summary>
        [System.ComponentModel.DefaultValue(true)]
        public bool RecursiveGroupMembership { get; set; }
        #endregion
    }
}
