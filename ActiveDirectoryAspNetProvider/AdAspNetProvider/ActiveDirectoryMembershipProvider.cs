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
    public class ActiveDirectoryMembershipProvider : System.Web.Security.ActiveDirectoryMembershipProvider
    {
        #region Private variables
        private ActiveDirectory.AdConnection adConnect;
        private NameValueCollection admpConfig;
        #endregion

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
                name = "ActiveDirectoryMembershipProvider";
            }

            // Provide description.
            if (string.IsNullOrWhiteSpace(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Active Directory Membership Provicder");
            }

            // Process configuration.
            this.Config = new ProviderConfiguration(name, config);

            // If needed to check allowedRoles, get AdConnection.
            if (this.Config.AllowedGroups.Any())
            {
                this.adConnect = new ActiveDirectory.AdConnection(this.Config);
            }

            // Process config class for base provider to avoid errors.
            this.admpConfig = new NameValueCollection();
            List<string> admpAllowedConfig = new List<string>() { "connectionStringName", "connectionUsername", "connectionPassword", "connectionProtection",
                "enablePasswordReset", "enableSearchMethods", "applicationName", "description", "requiresUniqueEmail", "clientSearchTimeout",
                "serverSearchTimeout", "attributeMapPasswordQuestion", "attributeMapPasswordAnswer", "attributeMapFailedPasswordAnswerCount", "attributeMapFailedPasswordAnswerTime", 
                "attributeMapFailedPasswordAnswerLockoutTime", "attributeMapEmail", "attributeMapUsername", "maxInvalidPasswordAttempts", "passwordAttemptWindow",
                "passwordAnswerAttemptLockoutDuration", "minRequiredPasswordLength", "minRequiredNonalphanumericCharacters", "passwordStrengthRegularExpression" };
            foreach (string configSetting in config.Keys)
            {
                // If is in allowed list, add value to new admpConfig.
                if (admpAllowedConfig.Contains(configSetting))
                {
                    this.admpConfig.Add(configSetting, config[configSetting]);
                }
            }

            // Initialize base class.
            base.Initialize(name, admpConfig);
        }

        /// <summary>
        /// Provider configuration
        /// </summary>
        private ProviderConfiguration Config { get; set; }

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

        /// <summary>
        /// Initialized AdConnection.
        /// </summary>
        /// <returns>True if connection has been initialized.</returns>
        private bool InitializeAdConnection()
        {
            // If connection already exists, return true.
            if (this.adConnect != null)
            {
                return true;
            }

            // Get connection.
            this.adConnect = new ActiveDirectory.AdConnection(this.Config);

            return (this.adConnect == null);
        }

        /// <summary>
        /// Initialize base ActiveDirectoryMembershipProvider.
        /// </summary>
        private void InitializeBaseProvider()
        {
            // Initialize base.
            base.Initialize(this.Name, this.admpConfig);
        }

        /// <summary>
        /// Validate user to make sure they have valid roles.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="password">Password to check.</param>
        /// <returns>True/false if user login is valid and if they are a member of allowed roles.</returns>
        public override bool ValidateUser(string username, string password)
        {
            // Check to make sure user if allowed, if appropriate.
            if (this.Config.AllowedUsers.Any() && !this.Config.AllowedUsers.Contains(username))
            {
                // Restricted users, and this user is not one of them.
                return false;
            }

            // Initialize AdConnection.
            this.InitializeAdConnection();

            // Determine if user is valid.
            var validUser = this.adConnect.ValidateUser(username, password);

            // If user is not valid, return now.
            if (!validUser)
            {
                return false;
            }

            // If allowedRoles is restricted, check further.
            if (this.Config.AllowedGroups.Any())
            {
                // Define private variables.
                string[] roles = null;

                // Check cache.  Use different key than ActiveDirectoryRoleProvider to avoid complications in case of different settings.
                string cacheKey = "__ACTIVEDIRECTORYMEMBERSHIPPROVIDER__" + this.Config.Name + "_" + username;
                HttpContext currentContext = HttpContext.Current;
                if (currentContext != null)
                {
                    ActiveDirectoryRoleProviderCache cache = (ActiveDirectoryRoleProviderCache)currentContext.Cache.Get(cacheKey);
                    if (cache != null)
                    {
                        // Value found in cache.  See if it contains any roles.
                        return ((cache.Roles != null) && (cache.Roles.Any()));
                    }
                }

                // Check if user has any roles.  If so, they can proceed.
                roles = this.adConnect.GetGroupsForUser(username, this.Config.RecursiveGroupMembership).ToArray();

                // Store value in cache.
                if (currentContext != null)
                {
                    currentContext.Cache.Insert(cacheKey, new ActiveDirectoryRoleProviderCache(roles), null, DateTime.Now.AddMinutes(this.Config.CacheDurationInMinutes), Cache.NoSlidingExpiration);
                }

                return ((roles != null) && (roles.Any()));
            }
            else
            {
                // User is valid.
                return true;
            }
        }
    }
}
