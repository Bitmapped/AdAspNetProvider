using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.Web.Security;
using System.Configuration;
using System.Configuration.Provider;

namespace ActiveDirectoryAspNetProvider
{
    public sealed class ActiveDirectoryRoleProvider : RoleProvider
    {
        // Define private variables.
        private string connectionString, connectionUsername, connectionPassword, connectionDomain;
        private string applicationName;
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

            // Provide default application name if needed.
            if (string.IsNullOrWhiteSpace(name))
            {
                name = "ActiveDirectoryRoleProvider";
            }

            // Provide description.
            if (string.IsNullOrWhiteSpace(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Active Directory Role Provider");
            }

            // Initialize base class.
            base.Initialize(name, config);

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

            // Get application name. Truncate to 256 characters.
            this.applicationName = String.IsNullOrWhiteSpace(config["applicationName"]) ? ActiveDirectoryLibrary.GetDefaultApplicationName() : config["applicationName"];
            this.applicationName = (this.applicationName.Length > 256) ? this.applicationName.Substring(0, 256) : this.applicationName;

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

            // Initialize library.
            this.adLibrary = new ActiveDirectoryLibrary(this.connectionString, this.connectionDomain, this.connectionUsername, this.connectionPassword, this.usersToIgnore, this.rolesToIgnore, this.rolesToRenameFrom, this.rolesToRenameTo, this.allowedUsers, this.allowedRoles, this.cacheRolesInCookie);
        }

        public override string ApplicationName
        {
            get
            {
                return this.applicationName;
            }
            set
            {
                this.applicationName = value;
            }
        }

        #region Unsupported functions.  Provider is read-only.
        /// <summary>
        /// Adding users to roles is not supported.
        /// </summary>
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            throw new NotSupportedException("This is a read-only provider.");
        }

        /// <summary>
        /// Creating a new role is not supported.
        /// </summary>
        public override void CreateRole(string roleName)
        {
            throw new NotSupportedException("This is a read-only provider.");
        }

        /// <summary>
        /// Deleting a role is not supported.
        /// </summary>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            throw new NotSupportedException("This is a read-only provider.");
        }

        /// <summary>
        /// Removing users from roles is not supported.
        /// </summary>
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            throw new NotSupportedException("This is a read-only provider.");
        }
        #endregion

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            return this.adLibrary.FindUsersInRole(roleName, usernameToMatch);
        }

        public override string[] GetAllRoles()
        {
            return this.adLibrary.GetAllRoles();
        }

        public override string[] GetRolesForUser(string username)
        {
            return this.adLibrary.GetRolesForUser(username);
        }

        public override string[] GetUsersInRole(string roleName)
        {
            return this.adLibrary.GetUsersInRole(roleName);
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            return this.adLibrary.IsUserInRole(username, roleName);
        }

        public override bool RoleExists(string roleName)
        {
            return this.adLibrary.RoleExists(roleName);
        }




    }
}
