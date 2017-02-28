using System;
using System.Linq;
using System.Web;
using System.Web.Caching;
using System.Web.Security;
using System.Collections.Specialized;
using System.DirectoryServices.AccountManagement;

namespace AdAspNetProvider
{
    public class ActiveDirectoryMembershipProvider : MembershipProvider
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
                this.adConnect = new ActiveDirectory.Tools(this.Config);
            }

            // Initialize base class.
            base.Initialize(name, config);
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
        #endregion

        /// <summary>
        /// Initialize AdConnection.
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
            this.adConnect = new ActiveDirectory.Tools(this.Config);

            return (this.adConnect == null);
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
                roles = this.adConnect.GetGroupNamesForUser(username, this.Config.RecursiveGroupMembership).ToArray();

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

        /// <summary>
        /// Search for users by their e-mail address.
        /// </summary>
        /// <param name="emailToMatch">E-mail address to match.</param>
        /// <param name="pageIndex">Index for paging.</param>
        /// <param name="pageSize">Number of users for page.</param>
        /// <param name="totalRecords">Total number of users returned.</param>
        /// <returns>Collection of matching users.</returns>
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            // Verify that search methods are allowed.
            if (this.Config.EnableSearchMethods == false)
            {
                throw new NotSupportedException("Search methods are not enabled.");
            }

            // Find users.
            var users = this.adConnect.FindUsersByEmail(emailToMatch, pageIndex, pageSize);

            // Process users to create collection.
            var collection = new MembershipUserCollection();
            foreach (UserPrincipal user in users)
            {
                var membershipUser = new MembershipUser(providerName: this.Config.Name,
                                                    name: this.adConnect.GetNameFromPrincipal(user),
                                                    providerUserKey: user.Sid.ToString(),
                                                    email: user.EmailAddress,
                                                    passwordQuestion: "",
                                                    comment: "",
                                                    isApproved: true,
                                                    isLockedOut: user.IsAccountLockedOut(),
                                                    creationDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastLoginDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastActivityDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastPasswordChangedDate: user.LastPasswordSet.HasValue ? user.LastPasswordSet.Value : DateTime.Now,
                                                    lastLockoutDate: user.AccountLockoutTime.HasValue ? user.AccountLockoutTime.Value : DateTime.Now
                                                    );

                collection.Add(membershipUser);
            }

            // Assign total number of records.
            totalRecords = collection.Count;

            return collection;
        }

        /// <summary>
        /// Search for users by their name.
        /// </summary>
        /// <param name="emailToMatch">E-mail address to match.</param>
        /// <param name="pageIndex">Index for paging.</param>
        /// <param name="pageSize">Number of users for page.</param>
        /// <param name="totalRecords">Total number of users returned.</param>
        /// <returns>Collection of matching users.</returns>
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            // Verify that search methods are allowed.
            if (this.Config.EnableSearchMethods == false)
            {
                throw new NotSupportedException("Search methods are not enabled.");
            }

            // Find users.
            var users = this.adConnect.FindUsersByName(usernameToMatch, pageIndex, pageSize);

            // Process users to create collection.
            var collection = new MembershipUserCollection();
            foreach (UserPrincipal user in users)
            {
                var membershipUser = new MembershipUser(providerName: this.Config.Name,
                                                    name: this.adConnect.GetNameFromPrincipal(user),
                                                    providerUserKey: user.Sid.ToString(),
                                                    email: user.EmailAddress,
                                                    passwordQuestion: "",
                                                    comment: "",
                                                    isApproved: true,
                                                    isLockedOut: user.IsAccountLockedOut(),
                                                    creationDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastLoginDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastActivityDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastPasswordChangedDate: user.LastPasswordSet.HasValue ? user.LastPasswordSet.Value : DateTime.Now,
                                                    lastLockoutDate: user.AccountLockoutTime.HasValue ? user.AccountLockoutTime.Value : DateTime.Now
                                                    );

                collection.Add(membershipUser);
            }

            // Assign total number of records.
            totalRecords = collection.Count;

            return collection;
        }

        /// <summary>
        /// Get all users.
        /// </summary>
        /// <param name="pageIndex">Page index.</param>
        /// <param name="pageSize">Page size.</param>
        /// <param name="totalRecords">Out parameter for total number of records in collection.</param>
        /// <returns>Collection of MembershipUser records.</returns>
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            // Verify that search methods are allowed.
            if (this.Config.EnableSearchMethods == false)
            {
                throw new NotSupportedException("Search methods are not enabled.");
            }

            // Get users.
            var users = this.adConnect.GetAllUsers(pageIndex, pageSize);

            // Process users to create collection.
            var collection = new MembershipUserCollection();
            foreach (UserPrincipal user in users)
            {
                var membershipUser = new MembershipUser(providerName: this.Config.Name,
                                                    name: this.adConnect.GetNameFromPrincipal(user),
                                                    providerUserKey: user.Sid.ToString(),
                                                    email: user.EmailAddress,
                                                    passwordQuestion: "",
                                                    comment: "",
                                                    isApproved: true,
                                                    isLockedOut: user.IsAccountLockedOut(),
                                                    creationDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastLoginDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastActivityDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastPasswordChangedDate: user.LastPasswordSet.HasValue ? user.LastPasswordSet.Value : DateTime.Now,
                                                    lastLockoutDate: user.AccountLockoutTime.HasValue ? user.AccountLockoutTime.Value : DateTime.Now
                                                    );

                collection.Add(membershipUser);
            }

            // Assign total number of records.
            totalRecords = collection.Count;

            return collection;
        }


        /// <summary>
        /// Gets user matching specified username.
        /// </summary>
        /// <param name="username">Username to search.</param>
        /// <param name="userIsOnline">Not used.</param>
        /// <returns>MembershipUser object for user if it exists, otherwise null.</returns>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            // Initialize AdConnection.
            this.InitializeAdConnection();

            // Get user.
            var user = this.adConnect.GetUser(username);

            // If user was not found, return null.
            if (user == null)
            {
                return null;
            }

            // Create new membershipUser.
            var membershipUser = new MembershipUser(providerName: this.Config.Name,
                                                    name: this.adConnect.GetNameFromPrincipal(user),
                                                    providerUserKey: user.Sid.ToString(),
                                                    email: user.EmailAddress,
                                                    passwordQuestion: "",
                                                    comment: "",
                                                    isApproved: true,
                                                    isLockedOut: user.IsAccountLockedOut(),
                                                    creationDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastLoginDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastActivityDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastPasswordChangedDate: user.LastPasswordSet.HasValue ? user.LastPasswordSet.Value : DateTime.Now,
                                                    lastLockoutDate: user.AccountLockoutTime.HasValue ? user.AccountLockoutTime.Value : DateTime.Now
                                                    );

            return membershipUser;
        }

        /// <summary>
        /// Gets user matching specified key (SID).
        /// </summary>
        /// <param name="providerUserKey">Key to search for (SID).</param>
        /// <param name="userIsOnline">Not used.</param>
        /// <returns>MembershipUser object for user if it exists, otherwise null.</returns>
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            // Initialize AdConnection.
            this.InitializeAdConnection();

            // Get user.
            var user = this.adConnect.GetUserBySid((string)providerUserKey);

            // If user was not found, return null.
            if (user == null)
            {
                return null;
            }

            // Create new membershipUser.
            var membershipUser = new MembershipUser(providerName: this.Config.Name,
                                                    name: this.adConnect.GetNameFromPrincipal(user),
                                                    providerUserKey: user.Sid.ToString(),
                                                    email: user.EmailAddress,
                                                    passwordQuestion: "",
                                                    comment: "",
                                                    isApproved: true,
                                                    isLockedOut: user.IsAccountLockedOut(),
                                                    creationDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastLoginDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastActivityDate: user.LastLogon.HasValue ? user.LastLogon.Value : DateTime.Now,
                                                    lastPasswordChangedDate: user.LastPasswordSet.HasValue ? user.LastPasswordSet.Value : DateTime.Now,
                                                    lastLockoutDate: user.AccountLockoutTime.HasValue ? user.AccountLockoutTime.Value : DateTime.Now
                                                    );

            return membershipUser;
        }

        /// <summary>
        /// Finds the username associated with a given email address.
        /// </summary>
        /// <param name="email">E-mail address for search.</param>
        /// <returns>Associated username or null.</returns>
        public override string GetUserNameByEmail(string email)
        {
            // Initialize AdConnection.
            this.InitializeAdConnection();

            // Get user.
            var user = this.adConnect.GetUserByEmail(email);

            if (user == null)
            {
                return null;
            }

            return this.adConnect.GetNameFromPrincipal(user);
        }

        #region Unsupported methods and properties

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return true;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            // If silently ignoring not supported methods/properties, return default value.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return true;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                // Set status to true.
                status = MembershipCreateStatus.Success;

                return new MembershipUser(providerName: this.Config.Name,
                                                    name: username,
                                                    providerUserKey: providerUserKey,
                                                    email: email,
                                                    passwordQuestion: passwordQuestion,
                                                    comment: passwordAnswer,
                                                    isApproved: isApproved,
                                                    isLockedOut: false,
                                                    creationDate: DateTime.Now,
                                                    lastLoginDate: DateTime.Now,
                                                    lastActivityDate: DateTime.Now,
                                                    lastPasswordChangedDate: DateTime.Now,
                                                    lastLockoutDate: DateTime.Now
                                                    );
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            // If silently ignoring not supported methods/properties, return default value.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return true;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.  Always returns false.
        /// </summary>
        public override bool EnablePasswordReset
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Not implemented.  Always returns false.
        /// </summary>
        public override bool EnablePasswordRetrieval
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override int GetNumberOfUsersOnline()
        {
            // If silently ignoring not supported methods/properties, return default value.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return 0;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override string GetPassword(string username, string answer)
        {
            // If silently ignoring not supported methods/properties, return default value.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return String.Empty;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override int MaxInvalidPasswordAttempts
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return 0;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override int MinRequiredNonAlphanumericCharacters
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return 0;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override int MinRequiredPasswordLength
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return 0;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override int PasswordAttemptWindow
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return 0;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override MembershipPasswordFormat PasswordFormat
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return MembershipPasswordFormat.Hashed;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override string PasswordStrengthRegularExpression
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return String.Empty;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool RequiresQuestionAndAnswer
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return false;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool RequiresUniqueEmail
        {
            get
            {
                // If silently ignoring not supported methods/properties, return default value.
                if (this.Config.SilentlyIgnoreNotSupported)
                {
                    return false;
                }

                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override string ResetPassword(string username, string answer)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return String.Empty;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override bool UnlockUser(string userName)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return true;
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override void UpdateUser(MembershipUser user)
        {
            // If silently ignoring not supported methods/properties, return that action was completed.
            if (this.Config.SilentlyIgnoreNotSupported)
            {
                return;
            }

            throw new NotSupportedException();
        }

        #endregion

    }
}
