using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AdAspNetProvider.ActiveDirectory.Support;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;

namespace AdAspNetProvider.ActiveDirectory
{
    public class AdConnection
    {
        #region Private variables
        private AdAspNetProvider.ActiveDirectory.Support.ActiveDirectory adService;
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
        public AdConnection(string server, string username, string password)
            : this(new AdConfiguration{ Server = server, Username = username, Password = password })
        { }

        /// <summary>
        /// Create new Active Directory connection.
        /// </summary>
        /// <param name="configuration">Configuration settings to use.</param>
        public AdConnection(AdConfiguration configuration)
        {
            // Verify a valid configuration object was passed.
            if (configuration == null)
            {
                throw new ArgumentException("A valid configuration was not specified.");
            }

            // Store configuration.
            this.Config = configuration;

            // Instantiate adService.
            this.adService = new Support.ActiveDirectory(configuration);
        }
        #endregion

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
        /// Determine if specified group exists.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <returns>True/false if group exists.</returns>
        public bool GroupExists(string group)
        {
            return this.adService.GroupExists(this.GetRenamedFromGroup(group));
        }

        /// <summary>
        /// Get all groups.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public ICollection<string> GetAllGroups(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals for all groups.
            var groupPrincipals = this.adService.GetAllGroups(pageIndex, pageSize, sortOrder);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            // Process groups for rename, ignore, and allowed.
            groups = this.ProcessRemameIgnoredAllowedGroups(groups);

            return groups;
        }

        /// <summary>
        /// Get all users.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all users.</returns>
        public ICollection<string> GetAllUsers(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principals for all users.
            var userPrincipals = this.adService.GetAllUsers(pageIndex, pageSize, sortOrder);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

            // Process entries.
            var users = this.GetNamesFromPrincipals(userPrincipals);

            return users;
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
        /// Get users within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public ICollection<string> GetUsersForGroup(string group, bool recursive = true)
        {
            // Get principals for users.
            var userPrincipals = this.adService.GetUsersForGroup(this.GetRenamedFromGroup(group), recursive);

            // Process users for ignore and allowed.
            userPrincipals = this.ProcessIgnoredAllowedUsers(userPrincipals);

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
        public ICollection<string> GetGroupsForUser(string username, bool recursive = true)
        {
            // Get principals for groups.
            var groupPrincipals = this.adService.GetGroupsForUser(username, recursive);

            // Process entries.
            var groups = this.GetNamesFromPrincipals(groupPrincipals);

            // Process groups for rename, ignore, and allowed.
            groups = this.ProcessRemameIgnoredAllowedGroups(groups);

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

        #region Support class for processing entries.
        /// <summary>
        /// Processes list of principals to get names.
        /// </summary>
        /// <param name="principals">Collection of principals.</param>
        /// <returns>Collection of names.</returns>
        private ICollection<string> GetNamesFromPrincipals(ICollection<Principal> principals)
        {
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
                // Extract name from underlying DirectoryEntry object.
                principalName = ((DirectoryEntry)principal.GetUnderlyingObject()).Properties[this.Config.IdentityType.ToString()].Value.ToString();
            }
            catch { }

            return principalName;
        }
        #endregion

        #region Support classes for cleaning up user and group members and names.
        /// <summary>
        /// Gets renamed name for specified group.
        /// </summary>
        /// <param name="renameFrom">Group to rename.</param>
        /// <returns>Renamed name.</returns>
        private string GetRenamedGroup(string renameFrom)
        {
            // If rename list contains renameFrom, get its value.
            if (this.Config.GroupsToRename.ContainsKey(renameFrom))
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
            if (this.Config.GroupsToRename.ContainsValue(renameTo))
            {
                // Try fetching corresponding rename entry.
                var rename = this.Config.GroupsToRename.FirstOrDefault(x => x.Value == renameTo);

                return rename.Key;
            }
            else
            {
                // Rename did not exist.  Return original name.
                return renameTo;
            }
        }

        /// <summary>
        /// Processes collection of users to rename, ignore, and allow users.
        /// </summary>
        /// <param name="originalUsers">Original collection of users.</param>
        /// <returns>Processed collection of users.</returns>
        private ICollection<Principal> ProcessIgnoredAllowedUsers(ICollection<Principal> originalUsers)
        {
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
        /// Processes collection of groups to rename, ignore, and allow users.
        /// </summary>
        /// <param name="originalGroups">Original collection of groups.</param>
        /// <returns>Processed collection of groups.</returns>
        private ICollection<string> ProcessRemameIgnoredAllowedGroups(ICollection<string> originalGroups)
        {
            // New list of users.
            var processedGroups = new List<string>();

            // Iterate through list of original users.
            foreach (var originalGroup in originalGroups)
            {
                // Rename user.
                processedGroups.Add(GetRenamedGroup(originalGroup));
            }

            // Filter for allowed users.
            if (this.Config.AllowedGroups.Any())
            {
                // List of allowed users specified.  Compare against this list.
                processedGroups = processedGroups.Intersect(this.Config.AllowedGroups).ToList();
            }

            // Exclude ignored users.
            processedGroups = processedGroups.Except(this.Config.GroupsToIgnore).ToList();

            return processedGroups;
        }
        #endregion

    }
}
