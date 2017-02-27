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
        /// Get all groups.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public ICollection<Principal> GetAllGroups(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals for all groups.
            var groupPrincipals = this.adService.GetAllGroups(pageIndex, pageSize, sortOrder);

            // Process groups for rename, ignore, and allowed.
            groupPrincipals = this.ProcessIgnoreAllowedGroups(groupPrincipals);

            return groupPrincipals;
        }

        /// <summary>
        /// Get all group names.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public ICollection<string> GetAllGroupNames(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get group principals.
            var groupPrincipals = this.GetAllGroups(pageIndex, pageSize, sortOrder);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            return groups;
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
        /// Get all users.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public ICollection<Principal> GetAllUsers(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals for all users.
            var userPrincipals = this.adService.GetAllUsers(pageIndex, pageSize, sortOrder);

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
        public ICollection<string> GetAllUserNames(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Process entries.
            var userPrincipals = this.GetAllUsers(pageIndex, pageSize, sortOrder);

            // Process entries.
            var users = this.GetNamesFromPrincipals(userPrincipals);

            return users;
        }

        /// <summary>
        /// Find all users whose e-mail address matches the given string.
        /// </summary>
        /// <param name="email">E-mail address (full or partial) to match.</param>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public ICollection<Principal> FindUsersByEmail(string email, int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
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
        public ICollection<Principal> FindUsersByName(string username, int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = IdentityType.SamAccountName)
        {
            // Get principals that match email.
            var userPrincipals = this.adService.FindUsersByName(username, pageIndex, pageSize, sortOrder);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
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
        /// Get users within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public ICollection<Principal> GetUsersForGroup(string group, bool recursive = true)
        {
            // Get principals for users.
            var userPrincipals = this.adService.GetUsersForGroup(this.GetRenamedFromGroup(group), recursive);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            return userPrincipals;
        }

        /// <summary>
        /// Get user names within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public ICollection<string> GetUserNamesForGroup(string group, bool recursive = true)
        {
            // Process users for ignore and allowed.
            var userPrincipals = this.GetUsersForGroup(group, recursive);

            // Process entries.
            var users = this.GetNamesFromPrincipals(userPrincipals);

            return users;
        }

        /// <summary>
        /// Get list of groups for this user is a member.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="recursive">Recursive search for groups.</param>
        /// <returns>Collection of groups for which this user is a member.</returns>
        public ICollection<Principal> GetGroupsForUser(string username, bool recursive = true)
        {
            // Get principals for groups.
            var groupPrincipals = this.adService.GetGroupsForUser(username, recursive);

            // Process groups for rename, ignore, and allowed.
            groupPrincipals = this.ProcessIgnoreAllowedGroups(groupPrincipals);

            return groupPrincipals;
        }

        /// <summary>
        /// Get list of group names for this user is a member.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="recursive">Recursive search for groups.</param>
        /// <returns>Collection of groups for which this user is a member.</returns>
        public ICollection<string> GetGroupNamesForUser(string username, bool recursive = true)
        {
            // Process groups for rename, ignore, and allowed.
            var groupPrincipals = this.GetGroupsForUser(username, recursive);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            return groups;
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
        /// Processes list of principals to get names.
        /// </summary>
        /// <param name="principals">Collection of principals.</param>
        /// <returns>Collection of names.</returns>
        public ICollection<string> GetNamesFromPrincipals(ICollection<Principal> principals)
        {
            // If there are no principals, return empty list.
            if (principals == null)
            {
                return new List<string>();
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

        /// <summary>
        /// Gets the specified name for one principal.
        /// </summary>
        /// <param name="principal">Principal to process.</param>
        /// <returns>Name for principal.</returns>
        public string GetNameFromPrincipal(Principal principal)
        {
            // Get name of principal.
            string principalName = null;
            try
            {
                // If principal is a group object, try to perform rename.
                if (principal is GroupPrincipal)
                {
                    if (this.Config.IdentityType == IdentityType.UserPrincipalName)
                    {
                        // UserPrincipalName is null for groups. Use Name value instead.
                        principalName = ((DirectoryEntry)principal.GetUnderlyingObject()).Properties[IdentityType.Name.ToString()].Value.ToString();
                    }
                    else
                    {
                        // Name exists in correct format for all IdentityTypes except UserPrincipalName. Use correct format.
                        principalName = ((DirectoryEntry)principal.GetUnderlyingObject()).Properties[this.Config.IdentityType.ToString()].Value.ToString();
                    }

                    principalName = this.GetRenamedGroup(principalName);
                }
                else
                {
                    // Principal is not a group. Use specified format.
                    principalName = ((DirectoryEntry)principal.GetUnderlyingObject()).Properties[this.Config.IdentityType.ToString()].Value.ToString();
                }
            }
            catch { }

            return principalName;
        }
        #endregion

        #region Support methods for renaming groups.
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
        #endregion

        #region Support methods for processing ignored and allowed users and groups.
        /// <summary>
        /// Processes collection of users to rename, ignore, and allow users.
        /// </summary>
        /// <param name="originalUsers">Original collection of users.</param>
        /// <returns>Processed collection of users.</returns>
        private ICollection<Principal> ProcessIgnoredAllowedUsers(ICollection<Principal> originalUsers)
        {
            // If there are no originalUsers, return empty list.
            if (originalUsers == null)
            {
                return new List<Principal>();
            }

            // New list of users.
            var processedUsers = new List<Principal>();

            // Filter for allowed users.
            if (this.Config.AllowedUsers.Any())
            {
                // Iterate through list of original users to see if they are allowed.
                foreach (var originalUser in originalUsers)
                {
                    if (this.Config.AllowedUsers.Contains(this.GetNameFromPrincipal(originalUser)))
                    {
                        // User on allowed list.  Add to output.
                        processedUsers.Add(originalUser);
                    }
                }
            }
            else
            {
                // Iterate through list of original users to see if they are to be ignored.
                foreach (var originalUser in originalUsers)
                {
                    if (this.Config.UsersToIgnore.Contains(this.GetNameFromPrincipal(originalUser)) == false)
                    {
                        // User not on ignore list.  Add to output.
                        processedUsers.Add(originalUser);
                    }
                }
            }

            return processedUsers;
        }

        /// <summary>
        /// Processes collection of groups to ignore and allow.
        /// </summary>
        /// <param name="originalGroups">Original collection of groups.</param>
        /// <returns>Processed collection of groups.</returns>
        private ICollection<Principal> ProcessIgnoreAllowedGroups(ICollection<Principal> originalGroups)
        {
            // If there are no originalGroups, return empty list.
            if (originalGroups == null)
            {
                return new List<Principal>();
            }

            // New list of users.
            var processedGroups = new List<Principal>();

            // Filter for allowed users.
            if (this.Config.AllowedGroups.Any())
            {
                // Iterate through Allowed Groups
                foreach (var allowedGroup in this.Config.AllowedGroups)
                {
                    //attempt to get group 
                    Principal principalItem = (Principal)originalGroups.FirstOrDefault(s => s.Name.Equals(allowedGroup));

                    //if found = allowed; add to output
                    if (principalItem != null)
                        processedGroups.Add(principalItem);
                }

                // Iterate through list of original users to see if they are allowed.
                /* foreach (var originalGroup in originalGroups)
                {
                    if (this.Config.AllowedGroups.Contains(GetRenamedGroup(this.GetNameFromPrincipal(originalGroup))))
                    {
                        // User on allowed list.  Add to output.
                        processedGroups.Add(originalGroup);
                    }
                } */
            }
            else
            {
                //assume all groups are allowed initially
                processedGroups = originalGroups.ToList<Principal>();

                // Iterate through Excluded Groups
                foreach (var ignoredGroup in this.Config.GroupsToIgnore)
                {
                    //attempt to get group 
                    Principal principalItem = (Principal)originalGroups.FirstOrDefault(s => s.Name.Equals(ignoredGroup));

                    //if found = exclude; remove from output
                    if (principalItem != null)
                        processedGroups.Remove(principalItem);
                }

                // Iterate through list of original users to see if they are to be ignored.
                /* foreach (var originalGroup in originalGroups)
                {
                    if (this.Config.GroupsToIgnore.Contains(GetRenamedGroup(this.GetNameFromPrincipal(originalGroup))) == false)
                    {
                        // User not on ignore list.  Add to output.
                        processedGroups.Add(originalGroup);
                    }
                } */
            }

            return processedGroups;
        }
    }
    }
