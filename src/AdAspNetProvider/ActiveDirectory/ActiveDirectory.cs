using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace AdAspNetProvider.ActiveDirectory
{
    public class ActiveDirectory
    {
        #region Private variables
        private AdAspNetProvider.ActiveDirectory.Service.AdService adService;
        #endregion

        /// <summary>
        /// Active Directory configuration settings
        /// </summary>
        public AdConfiguration Config { get; set; }

        #region Constructors
        /// <summary>
        /// Create new Active Directory connection.
        /// </summary>
        /// <param name="server">Server to connect to.</param>
        /// <param name="username">Username to use for connection.</param>
        /// <param name="password">Password to use for connection.</param>
        public ActiveDirectory(string server, string username, string password)
            : this(new AdConfiguration { Server = server, Username = username, Password = password })
        { }

        /// <summary>
        /// Create new Active Directory connection.
        /// </summary>
        /// <param name="configuration">Configuration settings to use.</param>
        public ActiveDirectory(AdConfiguration configuration)
        {
            // Verify a valid configuration object was passed.
            if (configuration == null)
            {
                throw new ArgumentException("A valid configuration was not specified.");
            }

            // Store configuration.
            this.Config = configuration;

            // Instantiate adService.
            this.adService = new Service.AdService(configuration);
        }
        #endregion

        #region Methods for groups
        /// <summary>
        /// Get all group names.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public IEnumerable<string> GetAllGroupNames(int? pageIndex = null, int? pageSize = null, IdentityType? sortOrder = null)
        {
            // Get group principals.
            var groupPrincipals = this.GetAllGroups(pageIndex, pageSize, sortOrder);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            return groups;
        }

        /// <summary>
        /// Get all groups.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public IEnumerable<Principal> GetAllGroups(int? pageIndex = null, int? pageSize = null, IdentityType? sortOrder = null)
        {
            // Get principals for all groups.
            var groupPrincipals = this.adService.GetAllGroups(pageIndex, pageSize, sortOrder);

            // Process groups for rename, ignore, and allowed.
            groupPrincipals = this.ProcessIgnoreAllowedGroups(groupPrincipals);

            return groupPrincipals;
        }
        /// <summary>
        /// Determine if specified group exists.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <returns>True/false if group exists.</returns>
        public bool GroupExists(string group)
        {
            return this.adService.GroupExists(this.GetRenamedFromGroup(group));
        }
        #endregion

        #region Methods for users.
        /// <summary>
        /// Find all users whose e-mail address matches the given string.
        /// </summary>
        /// <param name="email">E-mail address (full or partial) to match.</param>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public IEnumerable<Principal> FindUsersByEmail(string email, int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals that match email.
            var userPrincipals = this.adService.FindUsersByEmail(email, pageIndex, pageSize, sortOrder);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
        }

        /// <summary>
        /// Find all users whose username matches the given string.
        /// </summary>
        /// <param name="username">E-mail address (full or partial) to match.</param>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by account name.</param>
        /// <returns>Collection of all users.</returns>
        public IEnumerable<Principal> FindUsersByName(string username, int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = IdentityType.SamAccountName)
        {
            // Get principals that match email.
            var userPrincipals = this.adService.FindUsersByName(username, pageIndex, pageSize, sortOrder);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
        }

        /// <summary>
        /// Get all user names.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public IEnumerable<string> GetAllUserNames(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Process entries.
            var userPrincipals = this.GetAllUsers(pageIndex, pageSize, sortOrder);

            // Process entries.
            var users = this.GetNamesFromPrincipals(userPrincipals);

            return users;
        }

        /// <summary>
        /// Get all users.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public IEnumerable<Principal> GetAllUsers(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals for all users.
            var userPrincipals = this.adService.GetAllUsers(pageIndex, pageSize, sortOrder);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
        }

        /// <summary>
        /// Load the listed user.
        /// </summary>
        /// <param name="username">Username to load.</param>
        /// <returns>Object representing user or null if doesn't exist.</returns>
        public UserPrincipal GetUser(string username)
        {
            // Check to make sure user if allowed, if appropriate.
            if (this.Config.AllowedUsers.Any() && !this.Config.AllowedUsers.Contains(username))
            {
                // Restricted users, and this user is not one of them.
                return null;
            }

            var user = this.adService.GetUser(username);

            return user;
        }

        /// <summary>
        /// Load the listed user by email.
        /// </summary>
        /// <param name="username">Email to load.</param>
        /// <returns>Object representing user or null if doesn't exist.</returns>
        public UserPrincipal GetUserByEmail(string email)
        {
            var user = this.adService.GetUserByEmail(email);

            // Check to make sure user if allowed, if appropriate.
            if (this.Config.AllowedUsers.Any() && !this.Config.AllowedUsers.Contains(user.SamAccountName))
            {
                // Restricted users, and this user is not one of them.
                return null;
            }

            return user;
        }

        /// <summary>
        /// Load the listed user by Sid.
        /// </summary>
        /// <param name="sid">Sid to load.</param>
        /// <returns>Object representing user or null if doesn't exist.</returns>
        public UserPrincipal GetUserBySid(string sid)
        {
            var user = this.adService.GetUserBySid(sid);

            // Check to make sure user if allowed, if appropriate.
            if (this.Config.AllowedUsers.Any() && !this.Config.AllowedUsers.Contains(user.SamAccountName))
            {
                // Restricted users, and this user is not one of them.
                return null;
            }

            return user;
        }
        /// <summary>
        /// Determine if specified user exists.
        /// </summary>
        /// <param name="username">Username to test.</param>
        /// <returns>True/false if user exists.</returns>
        public bool UserExists(string username)
        {
            return this.adService.UserExists(username);
        }

        /// <summary>
        /// Validate that user is authorized.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="password">Password to check.</param>
        /// <returns>True/false if user can be validated.</returns>
        public bool ValidateUser(string username, string password)
        {
            // Check to make sure user if allowed, if appropriate.
            if (this.Config.AllowedUsers.Any() && !this.Config.AllowedUsers.Contains(username))
            {
                // Restricted users, and this user is not one of them.
                return false;
            }

            // Check to see if user is valid in Active Directory.
            var validUser = this.adService.ValidateUser(username, password);

            // If user is not valid, stop checking.
            if (!validUser)
            {
                return false;
            }

            // If list of allowed groups has not been specified, let valid user proceed.
            if (this.Config.AllowedGroups.Any() == false)
            {
                return true;
            }

            // If groups have been restricted, see if this user is a member of a valid group.
            var groups = this.GetGroupsForUser(username, this.Config.RecursiveGroupMembership);

            return groups.Any();
        }
        #endregion

        #region Methods for fetching user-group relationships.
        /// <summary>
        /// Get list of group names for this user is a member.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="recursive">Recursive search for groups.</param>
        /// <returns>Collection of groups for which this user is a member.</returns>
        public IEnumerable<string> GetGroupNamesForUser(string username, bool recursive = true)
        {
            // Process groups for rename, ignore, and allowed.
            var groupPrincipals = this.GetGroupsForUser(username, recursive);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            return groups;
        }

        /// <summary>
        /// Get list of groups for this user is a member.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="recursive">Recursive search for groups.</param>
        /// <returns>Collection of groups for which this user is a member.</returns>
        public IEnumerable<Principal> GetGroupsForUser(string username, bool recursive = true)
        {
            // Get principals for groups.
            var groupPrincipals = this.adService.GetGroupsForUser(username, recursive);

            // Process groups for rename, ignore, and allowed.
            groupPrincipals = this.ProcessIgnoreAllowedGroups(groupPrincipals);

            return groupPrincipals;
        }

        /// <summary>
        /// Get user names within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public IEnumerable<string> GetUserNamesForGroup(string group, bool recursive = true)
        {
            // Process users for ignore and allowed.
            var userPrincipals = this.GetUsersForGroup(group, recursive);

            // Process entries.
            var users = this.GetNamesFromPrincipals(userPrincipals);

            return users;
        }

        /// <summary>
        /// Get users within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public IEnumerable<Principal> GetUsersForGroup(string group, bool recursive = true)
        {
            // Get principals for users.
            var userPrincipals = this.adService.GetUsersForGroup(this.GetRenamedFromGroup(group), recursive);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
        }
        /// <summary>
        /// Determines if user is a member of group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="username">Username to test.</param>
        /// <param name="recursive">Check groups recursively.</param>
        /// <returns>True/false if user is a member of the specified group.</returns>
        public bool IsUserInGroup(string group, string username, bool recursive = true)
        {
            return this.adService.IsUserInGroup(this.GetRenamedFromGroup(group), username, recursive);
        }
        #endregion

        #region Support methods for processing principals.
        /// <summary>
        /// Gets the specified name for one principal.
        /// </summary>
        /// <param name="principal">Principal to process.</param>
        /// <returns>Name for principal.</returns>
        public string GetNameFromPrincipal(Principal principal)
        {
            // Get name of principal.
            try
            {
                // If principal is a group object, try to perform rename.
                if (principal is GroupPrincipal)
                {
                    switch (this.Config.IdentityType)
                    {
                        case IdentityType.SamAccountName:
                            return this.GetRenamedGroup(principal.SamAccountName);

                        case IdentityType.Name:
                        case IdentityType.UserPrincipalName:
                        default:
                            return this.GetRenamedGroup(principal.Name);

                        case IdentityType.DistinguishedName:
                            return this.GetRenamedGroup(principal.DistinguishedName);

                        case IdentityType.Sid:
                            return this.GetRenamedGroup(principal.Sid?.ToString());

                        case IdentityType.Guid:
                            return this.GetRenamedGroup(principal.Guid?.ToString());
                    }
                }
                else
                {
                    // Get principal name as is.
                    switch (this.Config.IdentityType)
                    {
                        case IdentityType.SamAccountName:
                            return principal.SamAccountName;

                        case IdentityType.Name:
                        default:
                            return principal.Name;

                        case IdentityType.UserPrincipalName:
                            return principal.UserPrincipalName;

                        case IdentityType.DistinguishedName:
                            return principal.DistinguishedName;

                        case IdentityType.Sid:
                            return principal.Sid?.ToString();

                        case IdentityType.Guid:
                            return principal.Guid?.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Processes list of principals to get names.
        /// </summary>
        /// <param name="principals">Collection of principals.</param>
        /// <returns>Collection of names.</returns>
        public IEnumerable<string> GetNamesFromPrincipals(IEnumerable<Principal> principals)
        {
            // If there are no principals, return empty list.
            if (principals == null)
            {
                return Enumerable.Empty<string>();
            }

            // Collection of names.
            var names = new List<string>();

            // Iterate through entries.
            foreach (var principal in principals)
            {
                var principalName = this.GetNameFromPrincipal(principal);

                // Add SAM name to list if not null.
                if (principalName != null)
                {
                    names.Add(principalName);
                }
            }

            return names;
        }
        #endregion

        #region Support methods for renaming groups.
        /// <summary>
        /// Given new name for renamed group, find original name.
        /// </summary>
        /// <param name="renameTo">New name for group.</param>
        /// <returns>Original name.</returns>
        private string GetRenamedFromGroup(string renameTo)
        {
            // If rename list contains renameTo, get its key.
            if (!String.IsNullOrWhiteSpace(renameTo))
            {
                // Try fetching corresponding rename entry.
                var rename = this.Config.GroupsToRename.Where(x => x.Value == renameTo);

                // If a name was returned, use it.
                if (rename.Any())
                {
                    return rename.First().Key;
                }
            }

            // Rename did not exist.  Return original name.
            return renameTo;

        }

        /// <summary>
        /// Gets renamed name for specified group.
        /// </summary>
        /// <param name="renameFrom">Group to rename.</param>
        /// <returns>Renamed name.</returns>
        private string GetRenamedGroup(string renameFrom)
        {
            // If rename list contains renameFrom, get its value.
            if (!String.IsNullOrWhiteSpace(renameFrom) && this.Config.GroupsToRename.ContainsKey(renameFrom))
            {
                return this.Config.GroupsToRename[renameFrom];
            }
            else
            {
                return renameFrom;
            }
        }
        #endregion

        #region Support methods for processing ignored and allowed users and groups.
        /// <summary>
        /// Processes collection of groups to ignore and allow.
        /// </summary>
        /// <param name="originalGroups">Original collection of groups.</param>
        /// <returns>Processed collection of groups.</returns>
        private IEnumerable<Principal> ProcessIgnoreAllowedGroups(IEnumerable<Principal> originalGroups)
        {
            // If there are no originalGroups, return empty list.
            if (originalGroups == null)
            {
                return Enumerable.Empty<Principal>();
            }

            // New list of users.
            var processedGroups = new List<Principal>();

            // Filter for allowed users.
            if (this.Config.AllowedGroups.Any())
            {
                // Iterate through allowed groups.
                foreach (var allowedGroup in this.Config.AllowedGroups)
                {
                    // Atempt to get group.
                    Principal principalItem = originalGroups.FirstOrDefault(s => this.GetNameFromPrincipal(s) == allowedGroup);

                    // If item was found, it is allowed. Add to output.
                    if (principalItem != null)
                    {
                        processedGroups.Add(principalItem);
                    }
                }
            }
            else
            {
                //assume all groups are allowed initially
                processedGroups = originalGroups.ToList<Principal>();

                // Iterate through Excluded Groups
                foreach (var ignoredGroup in this.Config.GroupsToIgnore)
                {
                    // Attempt to get group.
                    Principal principalItem = originalGroups.FirstOrDefault(s => this.GetNameFromPrincipal(s) == ignoredGroup);

                    // If item was found, it should be ignored. Remove from output.
                    if (principalItem != null)
                    {
                        processedGroups.Remove(principalItem);
                    }
                }
            }

            return processedGroups;
        }

        /// <summary>
        /// Processes collection of users to rename, ignore, and allow users.
        /// </summary>
        /// <param name="originalUsers">Original collection of users.</param>
        /// <returns>Processed collection of users.</returns>
        private IEnumerable<Principal> ProcessIgnoredAllowedUsers(IEnumerable<Principal> originalUsers)
        {
            // If there are no originalUsers, return empty list.
            if (originalUsers == null)
            {
                return Enumerable.Empty<Principal>();
            }

            // New list of users.
            var processedUsers = new List<Principal>();

            // Filter for allowed users.
            if (this.Config.AllowedUsers.Any())
            {
                // Iterate through Allowed Users
                foreach (var allowedUser in this.Config.AllowedUsers)
                {
                    // Attempt to get user.
                    Principal principalItem = originalUsers.FirstOrDefault(s => this.GetNameFromPrincipal(s) == allowedUser);

                    // If allowed user was found, it is allowed. Add it to output.
                    if (principalItem != null)
                    {
                        processedUsers.Add(principalItem);
                    }
                }
            }
            else
            {
                // Assume all users are allowed initially.
                processedUsers = originalUsers.ToList();

                // Iterate through Excluded Users
                foreach (var ignoredUser in this.Config.UsersToIgnore)
                {
                    // Attempt to get user.
                    Principal principalItem = originalUsers.FirstOrDefault(s => this.GetNameFromPrincipal(s) == ignoredUser);

                    // If user was found, it should be ignored. Remove it from output.
                    if (principalItem != null)
                    {
                        processedUsers.Remove(principalItem);
                    }
                }
            }

            return processedUsers;
        }
        #endregion 
    }
}
