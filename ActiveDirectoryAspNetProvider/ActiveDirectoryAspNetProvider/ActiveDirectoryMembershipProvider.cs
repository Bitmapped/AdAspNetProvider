using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Configuration.Provider;

namespace ActiveDirectoryAspNetProvider
{
    public class ActiveDirectoryMembershipProvider : System.Web.Security.ActiveDirectoryMembershipProvider
    {
        // Define private variables.
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

            // Initialize library.
            this.adLibrary = new ActiveDirectoryLibrary(config);

            // Remove processed elements from config to avoid error in base class.
            config.Remove("connectionDomain");
            config.Remove("usersToIgnore");
            config.Remove("rolesToIgnore");
            config.Remove("rolesToRenameFrom");
            config.Remove("rolesToRenameTo");
            config.Remove("allowedUsers");
            config.Remove("allowedRoles");
            config.Remove("cacheRolesInCookie");
            config.Remove("ignoreDefaultRoles");
            config.Remove("ignoreDefaultUsers");

            // Initialize base class.
            base.Initialize(name, config);            
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
            if (this.adLibrary.allowedRoles.Any())
            {
                // Check if user has any roles returned.  If so, they can proceed.
                var roles = this.adLibrary.GetRolesForUser(username);

                // If there is at least one role returned, return true.  Otherwise, return false so user cannot login.
                if (roles.Any())
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
