using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Configuration.Provider;

namespace ActiveDirectoryAspNetProvider
{
    class ActiveDirectoryMembershipProvider : System.Web.Security.ActiveDirectoryMembershipProvider
    {
        // Define private variables.
        private string connectionString, connectionUsername, connectionPassword, connectionDomain;
        private string usersToIgnore, rolesToIgnore, rolesToRenameFrom, rolesToRenameTo, allowedUsers, allowedRoles;
        bool cacheRolesInCookie = false;
        private ActiveDirectoryLibrary adLibrary;

        public override void Initialize(string name, NameValueCollection config)
        {
            // Check to ensure configuration is specified.
            if (config == null)
            {
                throw new ArgumentNullException("No configuration specified.");
            }

            // Provide default name if needed.
            if (string.IsNullOrWhiteSpace(name))
            {
                name = "ActiveDirectoryMembershipProvider";
            }

            // Provide description.
            if (string.IsNullOrWhiteSpace(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Active Directory Membership Provider");
            }

            // Get connection string.
            if (string.IsNullOrWhiteSpace(config["connectionStringName"]))
            {
                throw new ProviderException("Attribute 'connectionStringName' missing or empty.");
            }
            if (ConfigurationManager.ConnectionStrings[config["connectionStringName"]] == null)
            {
                throw new ProviderException(String.Format("Specified \"{0}\" connection string does not exist.", config["connectionStringName"]));
            }
            if (ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString.Substring(0, 7) != "LDAP://")
            {
                throw new ProviderException(String.Format("Specified \"{0}\" connection string is invalid.", config["connectionStringName"]));
            }
            this.connectionString = ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString;

            // Get connection username, password, domain.  Default to null if they don't exist.
            this.connectionUsername = string.IsNullOrWhiteSpace(config["connectionUsername"]) ? String.Empty : config["connectionUsername"];
            this.connectionPassword = string.IsNullOrWhiteSpace(config["connectionPassword"]) ? String.Empty : config["connectionPassword"];
            this.connectionDomain = string.IsNullOrWhiteSpace(config["connectionDomain"]) ? String.Empty : config["connectionDomain"];
            
            // Process username to remove any domain prefix.
            if (this.connectionUsername.IndexOf('\\') != -1)
            {
                this.connectionUsername = this.connectionUsername.Substring(this.connectionUsername.IndexOf('\\') + 1);
            }

            // Process users and groups to ignore.
            this.usersToIgnore = String.IsNullOrWhiteSpace(config["usersToIgnore"]) ? String.Empty : config["usersToIgnore"];
            this.rolesToIgnore = String.IsNullOrWhiteSpace(config["rolesToIgnore"]) ? String.Empty : config["rolesToIgnore"];

            // Process groups to rename from/to.
            this.rolesToRenameFrom = String.IsNullOrWhiteSpace(config["rolesToRenameFrom"]) ? String.Empty : config["rolesToRenameFrom"];
            this.rolesToRenameTo = String.IsNullOrWhiteSpace(config["rolesToRenameTo"]) ? String.Empty : config["rolesToRenameTo"];

            // Process allowed users and roles.
            this.allowedUsers = String.IsNullOrWhiteSpace(config["allowedUsers"]) ? String.Empty : config["allowedUsers"];
            this.allowedRoles = String.IsNullOrWhiteSpace(config["allowedRoles"]) ? String.Empty : config["allowedRoles"];

            // Process caching.
            if (!string.IsNullOrWhiteSpace(config["cacheRolesInCookie"]))
            {
                if (config["cacheRolesInCookie"].ToLower() == "true")
                {
                    this.cacheRolesInCookie = true;
                }
            }

            // Remove processed elements from config to avoid error in base class.
            config.Remove("connectionDomain");
            config.Remove("usersToIgnore");
            config.Remove("rolesToIgnore");
            config.Remove("rolesToRenameFrom");
            config.Remove("rolesToRenameTo");
            config.Remove("allowedUsers");
            config.Remove("allowedRoles");
            config.Remove("cacheRolesInCookie");

            // Initialize base class.
            base.Initialize(name, config);

            // Initialize library.
            this.adLibrary = new ActiveDirectoryLibrary(this.connectionString, this.connectionDomain, this.connectionUsername, this.connectionPassword, this.usersToIgnore, this.rolesToIgnore, this.rolesToRenameFrom, this.rolesToRenameTo, this.allowedUsers, this.allowedRoles, this.cacheRolesInCookie);
        }

        /// <summary>
        /// Validate user to make sure they have valid roles.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="password">Password to check.</param>
        /// <returns>True/false if user login is valid and if they are a member of allowed roles.</returns>
        public override bool ValidateUser(string username, string password)
        {
            // Determine if user is valid.
            bool validUser = base.ValidateUser(username, password);

            // If not a valid user, return now.
            if (!validUser)
            {
                return false;
            }

            // If allowedRoles is restricted, check further.
            if (!String.IsNullOrWhiteSpace(this.allowedRoles))
            {
                // Check if user has any roles returned.  If so, they can proceed.
                var roles = this.adLibrary.GetRolesForUser(username);

                // If there is at least one role returned, return true.  Otherwise, return false so user cannot login.
                if (roles.Count() >= 1)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                // Roles not restricted.  If user made it this far, they are valid.
                return true;
            }
        }
    }
}
