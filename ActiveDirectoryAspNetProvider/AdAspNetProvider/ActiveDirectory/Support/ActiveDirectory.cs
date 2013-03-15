using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using Logging = AdAspNetProvider.Logging;

namespace AdAspNetProvider.ActiveDirectory.Support
{
    public class ActiveDirectory
    {
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
            : this(new AdConfiguration{ Server = server, Username = username, Password = password })
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
            // Get new principal context.
            var context = this.GetPrincipalContext(false);

            return context.ValidateCredentials(username, password);
        }

        /// <summary>
        /// Load the listed group.
        /// </summary>
        /// <param name="group">Group to load.</param>
        /// <returns>Object representing group or null if doesn't exist.</returns>
        public GroupPrincipal GetGroup(string group)
        {
            // Get new principal context.
            var context = this.GetPrincipalContext();

            // Get group.
            var groupPrincipal = GroupPrincipal.FindByIdentity(context, this.Config.IdentityType, group);

            return groupPrincipal;
        }

        /// <summary>
        /// Load the listed user.
        /// </summary>
        /// <param name="username">Username to load.</param>
        /// <returns>Object representing user or null if doesn't exist.</returns>
        public UserPrincipal GetUser(string username)
        {
            // Get new principal context.
            var context = this.GetPrincipalContext();

            // Get user.
            var userPrincipal = UserPrincipal.FindByIdentity(context, this.Config.IdentityType, username);

            return userPrincipal;
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
            // Get new principal context.
            var context = this.GetPrincipalContext();

            // Get user principal.
            var userPrincipal = new UserPrincipal(context);

            return this.GetAllPrincipals(userPrincipal, pageIndex, pageSize, sortOrder);
        }

        /// <summary>
        /// Get all groups.
        /// </summary>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all groups.</returns>
        public ICollection<Principal> GetAllGroups(int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get new principal context.
            var context = this.GetPrincipalContext();

            // Get group principal.
            var groupPrincipal = new GroupPrincipal(context);

            return this.GetAllPrincipals(groupPrincipal, pageIndex, pageSize, sortOrder);
        }

        /// <summary>
        /// Gets all principal objects matching the search principal.
        /// </summary>
        /// <param name="searchPrincipal">Principal to use as basis of search.</param>
        /// <param name="pageIndex">Zero-based index of page to return, or null for all results.</param>
        /// <param name="pageSize">Number of items per page to return, or null for all results.</param>
        /// <param name="sortOrder">Sort order for results, or null to sort by configuration IdentityType.</param>
        /// <returns>Collection of all matching principals.</returns>
        private ICollection<Principal> GetAllPrincipals(Principal searchPrincipal, int? pageIndex = null, int? pageSize = null, Nullable<IdentityType> sortOrder = null)
        {
            // Get principalSearch for this element.
            var principalSearcher = new PrincipalSearcher(searchPrincipal);
            
            // Configure settings for underlying searcher.
            var underlyingSearcher = (DirectorySearcher)principalSearcher.GetUnderlyingSearcher();
            underlyingSearcher.PageSize = 0x200;
            underlyingSearcher.PropertiesToLoad.Add(this.Config.IdentityType.ToString().ToLower());

            if (sortOrder.HasValue)
            {
                underlyingSearcher.Sort = new SortOption(sortOrder.Value.ToString().ToLower(), SortDirection.Ascending);
                underlyingSearcher.PropertiesToLoad.Add(sortOrder.Value.ToString().ToLower());
            }
            else
            {
                underlyingSearcher.Sort = new SortOption(this.Config.IdentityType.ToString().ToLower(), SortDirection.Ascending);
            }

            // Get and process results.
            var principals = new List<Principal>();
            var principalResults = principalSearcher.FindAll();

            // Calculate begin and end points for results.
            int startIndex = 0, endIndex = int.MaxValue;
            if ((pageIndex != null) && (pageSize != null))
            {
                startIndex = pageIndex.Value * pageSize.Value;
                endIndex = (pageIndex.Value + 1) * pageSize.Value;
            }

            // Use enumerator to loop because of issues with errors on sometimes-returned invalid SIDs.
            // See: http://social.msdn.microsoft.com/Forums/en/csharpgeneral/thread/9dd81553-3539-4281-addd-3eb75e6e4d5d 
            var principalEnum = principalResults.GetEnumerator();
            int currentIndex = 0;
            while (principalEnum.MoveNext())
            {
                if ((startIndex <= currentIndex) && (currentIndex < endIndex))
                {
                    Principal newPrincipal = null;
                    try
                    {
                        newPrincipal = principalEnum.Current;

                        if (newPrincipal != null)
                        {
                            // Add group object to results.
                            principals.Add(newPrincipal);
                        }
                    }
                    catch (PrincipalOperationException pe)
                    {
                        // Log error.
                        Logging.Log.LogError(pe);

                        continue;
                    }
                }

                // Increment counter.
                currentIndex++;
            }

            return principals;            
        }

        /// <summary>
        /// Determine if specified group exists.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <returns>True/false if group exists.</returns>
        public bool GroupExists(string group)
        {
            // Attempt to get group.
            var groupPrincipal = this.GetGroup(group);

            // If group is null, does not exist.
            return (groupPrincipal != null);
        }

        /// <summary>
        /// Determine if specified user exists.
        /// </summary>
        /// <param name="username">Username to test.</param>
        /// <returns>True/false if user exists.</returns>
        public bool UserExists(string username)
        {
            // Atempt to get user.
            var userPrincipal = this.GetUser(username);

            // If user is null, does not exist.
            return (userPrincipal != null);
        }


        /// <summary>
        /// Get users within a group.
        /// </summary>
        /// <param name="group">Group to test.</param>
        /// <param name="recursive">Recursively search children.</param>
        /// <returns>Collection of users of group.</returns>
        public ICollection<Principal> GetUsersForGroup(string group, bool recursive = true)
        {
            // Get group object.
            var groupPrincipal = this.GetGroup(group);

            // If group doesn't exist, return null.
            if (groupPrincipal == null)
            {
                return null;
            }

            // Get and process results.
            var users = new List<Principal>();
            var principalResults = groupPrincipal.GetMembers(recursive);
            foreach (Principal user in principalResults)
            {
                if (user != null)
                {
                    // Add valid user object to results.
                    users.Add(user);
                }
            }

            return users;
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
            // For performance reasons in large settings, check on user rather than group.
            var userGroups = this.GetGroupsForUser(username, recursive);

            // Get user and group objects.
            var groupPrincipal = this.GetGroup(group);

            // If either user or group doesn't exist, return false.
            if ((groupPrincipal == null) || (userGroups == null))
            {
                return false;
            }

            // Return based on if userPrincipal is in groupMembers.
            return userGroups.Contains(groupPrincipal);
        }

        /// <summary>
        /// Get list of groups for this user is a member.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="recursive">Recursive search for groups.</param>
        /// <returns>Collection of groups for which this user is a member.</returns>
        public ICollection<Principal> GetGroupsForUser(string username, bool recursive = true)
        {
            // Get user object.
            var userPrincipal = this.GetUser(username);

            // If user doesn't exist, return null.
            if (userPrincipal == null)
            {
                return null;
            }

            // Get and process results.
            var groups = new List<Principal>();
            PrincipalSearchResult<Principal> principalResults;
            
            // Depending on values, perform direct or recursive search.
            if (recursive)
            {
                principalResults = userPrincipal.GetAuthorizationGroups();
            }
            else
            {
                principalResults = userPrincipal.GetGroups();
            }

            // Use group enumerator to loop because of issues with errors on sometimes-returned invalid SIDs.
            // See: http://social.msdn.microsoft.com/Forums/en/csharpgeneral/thread/9dd81553-3539-4281-addd-3eb75e6e4d5d 
            var groupEnum = principalResults.GetEnumerator();
            while (groupEnum.MoveNext())
            {
                Principal group = null;
                try
                {
                    group = groupEnum.Current;

                    if (group != null)
                    {
                        // Add group object to results.
                        groups.Add(group);
                    }
                }
                catch (PrincipalOperationException pe)
                {
                    // Log error.
                    Logging.Log.LogError(pe);

                    continue;
                }
            }

            return groups;
        }

        #region Support methods
        /// <summary>
        /// Get principal context.
        /// </summary>
        /// <param name="validateConnection">If true, attempts to validate connection.</param>
        /// <returns>PrincipalContextObject.</returns>
        private PrincipalContext GetPrincipalContext(bool validateConnection = true)
        {
            // Define variable to store context.
            PrincipalContext context = null;

            // Create connextion based on type.
            if (String.IsNullOrWhiteSpace(this.Config.Server))
            {
                // Get new context.  Do not perform any testing.
                context = new PrincipalContext(this.Config.ContextType);
            }
            else
            {
                // Server name was specified.  Get DNS values.
                var serverIPs = Dns.GetIpAddresses(this.Config.Server);
                if (!serverIPs.Any())
                {
                    throw new ArgumentException("Specified server cannot be found.");
                }

                // Loop through to repeat attemption connections to server 5 times.
                bool connectionFailed = false;
                for (int retryIdx = 0; retryIdx < 5; retryIdx++)
                {
                    // Loop through to attempt connection to each server.
                    foreach (var serverIP in serverIPs)
                    {
                        try
                        {
                            // Create new connection.  Method varies depending on if username and password are specified.
                            if (!String.IsNullOrWhiteSpace(this.Config.Username) && !String.IsNullOrWhiteSpace(this.Config.Password))
                            {
                                // Username and password specified.
                                context = new PrincipalContext(this.Config.ContextType, serverIP.ToString(), this.Config.Container, this.Config.ContextOptions, this.Config.Username, this.Config.Password);
                                
                                // Attempt to validate connection.
                                if (validateConnection)
                                {
                                    if (context.ValidateCredentials(this.Config.Username, this.Config.Password) == false)
                                    {
                                        throw new PrincipalOperationException("Cannot connect to specified server using provided credentials.");
                                    }
                                }
                            }
                            else
                            {
                                context = new PrincipalContext(this.Config.ContextType, serverIP.ToString(), this.Config.Container, this.Config.ContextOptions);

                                // Attempt to validate connection.
                                if (validateConnection)
                                {
                                    if (context.ValidateCredentials(null, null) == false)
                                    {
                                        throw new PrincipalOperationException("Cannot connect to specified server.");
                                    }
                                }
                            }

                            // Assume that connection did not fail.
                            connectionFailed = false;
                            break;
                        }
                        catch (PrincipalServerDownException)
                        {
                            // Record that connection failed.
                            connectionFailed = true;
                        }
                    }

                    // If connection did not fail, we can break out of loop.
                    if (!connectionFailed)
                    {
                        break;
                    }
                }

                // If connection still failed, throw exception.
                if (connectionFailed)
                {
                    var pe = new PrincipalServerDownException(this.Config.Server);

                    // Ensure error gets logged.                    
                    Logging.Log.LogError(pe);

                    throw pe;
                }
            }

            // Return principal context.
            return context;
        }
        #endregion

    }
}
