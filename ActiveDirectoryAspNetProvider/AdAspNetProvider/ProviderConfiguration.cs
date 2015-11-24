using AdAspNetProvider.ActiveDirectory;
using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Net;
using System.ComponentModel;

namespace AdAspNetProvider
{
    public class ProviderConfiguration : AdConfiguration
    {
        #region Constructor
        /// <summary>
        /// Constructor, processes input configuration parameters
        /// </summary>
        /// <param name="name">Name of provider.</param>
        /// <param name="config">Configuration settings.</param>
        public ProviderConfiguration(string name, NameValueCollection config)
            : base()
        {
            // Check to ensure configuration is specified.
            if (config == null)
            {
                throw new ArgumentNullException("No configuration specified.");
            }

            // Process connection string.
            if (string.IsNullOrWhiteSpace(config["connectionStringName"]))
            {
                throw new ProviderException("Attribute 'connectionStringName' missing or empty.");
            }
            if (ConfigurationManager.ConnectionStrings[config["connectionStringName"]] == null)
            {
                throw new ProviderException(string.Format("Specified \"{0}\" connection string does not exist.", config["connectionStringName"]));
            }
            var connectionString = ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString;
            if (connectionString.Substring(0, 7) != "LDAP://")
            {
                throw new ProviderException(String.Format("Specified \"{0}\" connection string is invalid.", config["connectionStringName"]));
            }
            this.ConnectionString = connectionString;
            this.ConnectionStringName = config["connectionStringName"];

            // Parse connection string.
            var ldapUri = new Uri(connectionString);
            this.Server = ldapUri.DnsSafeHost;
            this.Container = ldapUri.AbsolutePath.Substring(1);

            // Store password and remove domain prefix.  Default to null if they don't exist.
            this.Username = string.IsNullOrWhiteSpace(config["connectionUsername"]) ? null : config["connectionUsername"];
            if ((this.Username != null) && (this.Username.IndexOf('\\') != -1))
            {
                this.Username = this.Username.Substring(this.Username.IndexOf('\\') + 1);
            }

            // Store password.  Default to null if it doesn't exist.
            this.Password = string.IsNullOrWhiteSpace(config["connectionPassword"]) ? null : config["connectionPassword"];

            // Store connection name.
            this.Name = name;

            // Process default users to ignore.
            if (!string.IsNullOrWhiteSpace(config["ignoreDefaultUsers"]) && (config["ignoreDefaultUsers"].ToLower() == "false"))
            {
                this.IgnoreDefaultUsers = false;

                // Empty IgnoreUsers.
                this.UsersToIgnore.Clear();
            }
            else
            {
                this.IgnoreDefaultUsers = true;
            }

            // Process recursive role membership.
            if (!string.IsNullOrWhiteSpace(config["recursiveRoleMembership"]) && (config["recursiveRoleMembership"].ToLower() == "true"))
            {
                this.RecursiveGroupMembership = true;
            }
            else
            {
                this.RecursiveGroupMembership = false;
            }

            // Process users to ignore.
            if (!String.IsNullOrWhiteSpace(config["usersToIgnore"]))
            {
                this.UsersToIgnore.AddRange(config["usersToIgnore"].Split(',').Select(user => user.Trim()));
            }

            // Process default roles to ignore.
            if (!string.IsNullOrWhiteSpace(config["ignoreDefaultRoles"]) && (config["ignoreDefaultRoles"].ToLower() == "false"))
            {
                this.IgnoreDefaultRoles = false;

                // Empty IgnoreRoles.
                this.GroupsToIgnore.Clear();
            }
            else
            {
                this.IgnoreDefaultRoles = true;
            }

            // Process roles to ignore.
            if (!String.IsNullOrWhiteSpace(config["rolesToIgnore"]))
            {
                this.GroupsToIgnore.AddRange(config["rolesToIgnore"].Split(',').Select(role => role.Trim()));
            }

            // Process allowed users.
            if (!String.IsNullOrWhiteSpace(config["allowedUsers"]))
            {
                this.AllowedUsers.AddRange(config["allowedUsers"].Split(',').Select(user => user.Trim()));
            }

            // Process allowed roles.
            if (!String.IsNullOrWhiteSpace(config["allowedRoles"]))
            {
                this.AllowedGroups.AddRange(config["allowedRoles"].Split(',').Select(role => role.Trim()));
            }

            // Process roles to rename.
            if ((!String.IsNullOrWhiteSpace(config["rolesToRenameFrom"])) && (!String.IsNullOrWhiteSpace(config["rolesToRenameTo"])))
            {
                var rolesToRenameFrom = config["rolesToRenameFrom"].Split(',').Select(role => role.Trim()).ToList();
                var rolesToRenameTo = config["rolesToRenameTo"].Split(',').Select(role => role.Trim()).ToList();

                // Verify two lists have same number of members.
                if (rolesToRenameFrom.Count() != rolesToRenameTo.Count())
                {
                    throw new ProviderException("Must be same number of roles to rename from as to.");
                }

                // Add rename elements to list.
                for (int i = 0; i < rolesToRenameFrom.Count(); i++)
                {
                    try
                    {
                        if (!String.IsNullOrWhiteSpace(rolesToRenameFrom[i]) && !String.IsNullOrWhiteSpace(rolesToRenameTo[i]))
                        {
                            this.GroupsToRename.TryAdd(rolesToRenameFrom[i], rolesToRenameTo[i]);
                        }
                    }
                    catch (ArgumentException ex)
                    {
                        throw new ProviderException("Role name can only be renamed once.", ex);
                    }
                }
            }

            // Store application name.
            this.ApplicationName = config["applicationName"];
            
            // Set cache duration.
            if (!string.IsNullOrWhiteSpace(config["cacheDurationInMinutes"]))
            {
                try
                {
                    this.CacheDurationInMinutes = Convert.ToInt32(config["cacheDurationInMinutes"]);
                }
                catch { }
            }

            // Set maximum number of attempts.
            if (!string.IsNullOrWhiteSpace(config["maxAttempts"]))
            {
                try
                {
                    this.MaxAttempts = Convert.ToInt32(config["maxAttempts"]);
                }
                catch { }
            }

            // Set maximum number of server failures.
            if (!string.IsNullOrWhiteSpace(config["maxServerFailures"]))
            {
                try
                {
                    this.MaxServerFailures = Convert.ToInt32(config["maxServerFailures"]);
                }
                catch { }
            }

            // Set identity type.  User "attributeMapUsername" parameter to be consistent with Microsoft ActiveDirectoryMembershipProvider.
            if (!string.IsNullOrWhiteSpace(config["attributeMapUsername"]))
            {
                switch (config["attributeMapUsername"].ToLower())
                {
                    case "samaccountname":
                        this.IdentityType = IdentityType.SamAccountName;
                        break;

                    case "name":
                        this.IdentityType = IdentityType.Name;
                        break;

                    case "userprincipalname":
                    default:
                        this.IdentityType = IdentityType.UserPrincipalName;
                        break;

                    case "distinguishedname":
                        this.IdentityType = IdentityType.DistinguishedName;
                        break;

                    case "sid":
                        this.IdentityType = IdentityType.Sid;
                        break;

                    case "guid":
                        this.IdentityType = IdentityType.Guid;
                        break;
                }
            }

            // Process enable search methods.
            if (!string.IsNullOrWhiteSpace(config["enableSearchMethods"]) && (config["enableSearchMethods"].ToLower() == "true"))
            {
                this.EnableSearchMethods = true;
            }
            else
            {
                this.IgnoreDefaultUsers = false;
            }

            // Process ignore server IPs.
            if (!String.IsNullOrWhiteSpace(config["ignoreServerIpAddresses"]))
            {
                this.IgnoreServerIpAddresses.AddRange(config["ignoreServerIpAddresses"].Split(',').Select(ip => IPAddress.Parse(ip.Trim())));
            }

            // Process silently ignoring not supported methods and properties.
            if (!string.IsNullOrWhiteSpace(config["silentlyIgnoreNotSupported"]) && (config["silentlyIgnoreNotSupported"].ToLower() == "true"))
            {
                this.SilentlyIgnoreNotSupported = true;
            }
            else
            {
                this.IgnoreDefaultUsers = false;
            }
        }
        #endregion

        #region Properties
        /// <summary>
        /// Application name
        /// </summary>
        public string ApplicationName { get; set; }

        /// <summary>
        /// Connection string name
        /// </summary>
        public string ConnectionStringName { get; set; }

        /// <summary>
        /// Connection string
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Ignore default users
        /// </summary>
        [DefaultValue(true)]
        public bool IgnoreDefaultUsers { get; set; }

        /// <summary>
        /// Ignore default roles
        /// </summary>
        [DefaultValue(true)]
        public bool IgnoreDefaultRoles { get; set; }

        /// <summary>
        /// Allow use of search method functions.
        /// </summary>
        [DefaultValue(false)]
        public bool EnableSearchMethods { get; set; }

        /// <summary>
        /// Silently ignore or return generic values for not-implemented AD methods rather than throwing an exception.
        /// </summary>
        [DefaultValue(false)]
        public bool SilentlyIgnoreNotSupported { get; set; }
        #endregion
    }
}
