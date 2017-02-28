using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using System.Web.Security;
using System.Configuration;
using System.Configuration.Provider;
using System.Collections.Specialized;

namespace AdAspNetProvider
{
    public class ActiveDirectoryRoleProvider : RoleProvider
    {
        #region Private variables
        private ActiveDirectory.Tools adConnect;
        #endregion

        #region Initialization methods
        /// <summary>
        /// Initialize provider.
        /// </summary>
        /// <param name="name">Name of provider.</param>
        /// <param name="config">Configuration setttings.</param>
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
                config.Add("description", "Active Directory Role Provicder");
            }

            // Process configuration.
            this.Config = new ProviderConfiguration(name, config);

            // Get Active Directory connection.
            this.adConnect = new ActiveDirectory.Tools(this.Config);

            // Initialize base class.
            base.Initialize(name, config);
        }

        /// <summary>
        /// Provider configuration
        /// </summary>
        public ProviderConfiguration Config { get; set; }

        /// <summary>
        /// Application name
        /// </summary>
        public override string ApplicationName
        {
            get
            {
                return this.Config.ApplicationName;
            }
            set
            {
                throw new InvalidOperationException("Cannot change application name.");
            }
        }
        #endregion

        /// <summary>
        /// Find users in role.
        /// </summary>
        /// <param name="roleName">Role to check.</param>
        /// <param name="usernameToMatch">Username to match.</param>
        /// <returns>Users in role matching name.</returns>
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            // Verify that search methods are allowed.
            if (this.Config.EnableSearchMethods == false)
            {
                throw new NotSupportedException("Search methods are not enabled.");
            }

            // Get user names.
            var users = this.adConnect.GetUserNamesForGroup(roleName);

            // Find usernames that match.
            var matchingUsers = users.Where(user => user.Contains(usernameToMatch));

            return matchingUsers.ToArray();
        }

        /// <summary>
        /// Get listing of all roles.
        /// </summary>
        /// <returns>List of roles</returns>
        public override string[] GetAllRoles()
        {
            // Verify that search methods are allowed.
            if (this.Config.EnableSearchMethods == false)
            {
                throw new NotSupportedException("Search methods are not enabled.");
            }

            return this.adConnect.GetAllGroupNames().ToArray();
        }

        /// <summary>
        /// Get roles for specified user.
        /// </summary>
        /// <param name="username">User to check.</param>
        /// <returns>List of roles</returns>
        public override string[] GetRolesForUser(string username)
        {
            // Define private variables.
            string[] roles = null;

            // Check cache.
            string cacheKey = "__ACTIVEDIRECTORYROLEPROVIDER__" + this.Config.Name + "_" + username;
            HttpContext currentContext = HttpContext.Current;
            if (currentContext != null)
            {
                ActiveDirectoryRoleProviderCache cache = (ActiveDirectoryRoleProviderCache)currentContext.Cache.Get(cacheKey);
                if (cache != null)
                {
                    // Value found in cache.  Return it.
                    return cache.Roles;
                }
            }

            // Value not found in cache.  Get roles for specified user.
            roles = this.adConnect.GetGroupNamesForUser(username, this.Config.RecursiveGroupMembership).ToArray();

            // Store value in cache.
            if (currentContext != null)
            {
                currentContext.Cache.Insert(cacheKey, new ActiveDirectoryRoleProviderCache(roles), null, DateTime.Now.AddMinutes(this.Config.CacheDurationInMinutes), Cache.NoSlidingExpiration);
            }

            return roles;
        }

        /// <summary>
        /// Get users in specified role.
        /// </summary>
        /// <param name="roleName">Role to check.</param>
        /// <returns>List of users</returns>
        public override string[] GetUsersInRole(string roleName)
        {
            return this.adConnect.GetUserNamesForGroup(roleName, this.Config.RecursiveGroupMembership).ToArray();
        }

        /// <summary>
        /// Determine if user is in specified role.
        /// </summary>
        /// <param name="username">User to check</param>
        /// <param name="roleName">Role to check</param>
        /// <returns>True/false if user is in group</returns>
        public override bool IsUserInRole(string username, string roleName)
        {
            return this.adConnect.IsUserInGroup(roleName, username, this.Config.RecursiveGroupMembership);
        }

        /// <summary>
        /// Determine if role exists.
        /// </summary>
        /// <param name="roleName">Role to check</param>
        /// <returns>True/false if role exists</returns>
        public override bool RoleExists(string roleName)
        {
            return this.adConnect.GroupExists(roleName);
        }

        #region Unsupported methods and properties

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override void CreateRole(string roleName)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return true;
            }

            throw new NotSupportedException();
        }

        #endregion
    }
}
