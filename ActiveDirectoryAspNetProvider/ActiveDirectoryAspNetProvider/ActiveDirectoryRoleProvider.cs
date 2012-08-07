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
        private string applicationName;
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

            // Initialize library.
            this.adLibrary = new ActiveDirectoryLibrary(config);

            // Initialize base class.
            base.Initialize(name, config);
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
