using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AdAspNetProvider.ActiveDirectory;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Configuration;

namespace AdAspNetProvider.Provider
{
    public class ProviderConfiguration : AdAspNetProvider.ActiveDirectory.AdConfiguration
    {
        public ProviderConfiguration(NameValueCollection config) : base()
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
                throw new ProviderException(String.Format("Specified \"{0}\" connection string does not exist.", config["connectionStringName"]));
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
            if (this.Username.IndexOf('\\') != -1)
            {
                this.Username = this.Username.Substring(this.Username.IndexOf('\\') + 1);
            }

            // Store password.  Default to null if it doesn't exist.
            this.Password = string.IsNullOrWhiteSpace(config["connectionPassword"]) ? null : config["connectionPassword"];

            // Store connection name.
            this.Name = config["name"];

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
                            this.GroupsToRename.Add(rolesToRenameFrom[i], rolesToRenameTo[i]);
                        }
                    }
                    catch (ArgumentException ex)
                    {
                        throw new ProviderException("Role name can only be renamed once.", ex);
                    }
                }
            }

            // Process users to rename.
            if ((!String.IsNullOrWhiteSpace(config["usersToRenameFrom"])) && (!String.IsNullOrWhiteSpace(config["usersToRenameTo"])))
            {
                var usersToRenameFrom = config["usersToRenameFrom"].Split(',').Select(role => role.Trim()).ToList();
                var usersToRenameTo = config["usersToRenameTo"].Split(',').Select(role => role.Trim()).ToList();

                // Verify two lists have same number of members.
                if (usersToRenameFrom.Count() != usersToRenameTo.Count())
                {
                    throw new ProviderException("Must be same number of users to rename from as to.");
                }

                // Add rename elements to list.
                for (int i = 0; i < usersToRenameFrom.Count(); i++)
                {
                    try
                    {
                        if (!String.IsNullOrWhiteSpace(usersToRenameFrom[i]) && !String.IsNullOrWhiteSpace(usersToRenameTo[i]))
                        {
                            this.UsersToRename.Add(usersToRenameFrom[i], usersToRenameTo[i]);
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
            
            // Set default cache duration.
            this.CacheDurationInMinutes = 30;
            if (!string.IsNullOrWhiteSpace(config["cacheDurationInMinutes"]))
            {
                try
                {
                    this.CacheDurationInMinutes = Convert.ToInt32(config["cacheDurationInMinutes"]);
                }
                catch (Exception) { }
            }
        }

        /// <summary>
        /// Duration of cache (in minutes)
        /// </summary>
        [System.ComponentModel.DefaultValue(30)]
        public int CacheDurationInMinutes { get; set; }

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
        public bool IgnoreDefaultUsers { get; set; }

        /// <summary>
        /// Ignore default roles
        /// </summary>
        public bool IgnoreDefaultRoles { get; set; }

    }
}
