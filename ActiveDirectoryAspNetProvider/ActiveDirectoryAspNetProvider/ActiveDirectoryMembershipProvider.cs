using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Configuration.Provider;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;

namespace ActiveDirectoryAspNetProvider
{
    public class ActiveDirectoryMembershipProvider : System.Web.Security.ActiveDirectoryMembershipProvider
    {
        // Define private variables.
        private ActiveDirectoryLibrary adLibrary;
        private bool cacheUsers;
        private string name;

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
            this.name = name;

            // Provide description.
            if (string.IsNullOrWhiteSpace(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Active Directory Membership Provider");
            }      
      
            // Process user caching.
            if (!string.IsNullOrWhiteSpace(config["cacheUsers"]) && (config["cacheUsers"].ToLower() == "true"))
            {
                this.cacheUsers = true;
            }
            else
            {
                this.cacheUsers = false;
            }

            // Initialize library.
            this.adLibrary = new ActiveDirectoryLibrary(name, config);

            // Remove processed elements from config to avoid error in base class.
            config.Remove("connectionDomain");
            config.Remove("usersToIgnore");
            config.Remove("rolesToIgnore");
            config.Remove("rolesToRenameFrom");
            config.Remove("rolesToRenameTo");
            config.Remove("allowedUsers");
            config.Remove("allowedRoles");
            config.Remove("cacheRoles");
            config.Remove("cacheUsers");
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
                return roles.Any();
            }
            else
            {
                // Roles not restricted.  If user made it this far, they are valid.
                return true;
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            // If no username provided, return null.
            if (string.IsNullOrWhiteSpace(username))
            {
                return null;
            }

            // Determine session variable name.
            var sessName = this.name + "_Users";

            // See if user value has been cached.
            ActiveDirectorySessionCache sessionCache;
            if ((this.cacheUsers) && (HttpContext.Current.User.Identity != null))
            {
                // Attempt to load 
                if (HttpContext.Current.Session[sessName] != null)
                {
                    // Get string.  Split into array and return.
                    try
                    {
                        sessionCache = HttpContext.Current.Session[sessName] as ActiveDirectorySessionCache;
                        if ((sessionCache != null) && (sessionCache.Username == HttpContext.Current.User.Identity.Name) && (sessionCache.User != null))
                        {
                            return sessionCache.User;
                        }
                    }
                    catch (Exception)
                    {
                        // In case of error, continue on.
                    }
                }
            }

            // Get user from base class.
            var user = base.GetUser(username, userIsOnline);

            // Cache roles if currently logged in user is one we are searching for.
            if ((this.cacheUsers) && (HttpContext.Current.User.Identity != null) && (HttpContext.Current.User.Identity.Name == username))
            {
                // Initialize session cache if needed.
                if (HttpContext.Current.Session[sessName] == null)
                {
                    HttpContext.Current.Session[sessName] = new ActiveDirectorySessionCache();
                }

                // Store information in cache.
                sessionCache = HttpContext.Current.Session[sessName] as ActiveDirectorySessionCache;
                sessionCache.Username = username;
                sessionCache.User = user;
            }

            return user;
        }
    }
}
