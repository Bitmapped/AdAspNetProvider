using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;

namespace ActiveDirectoryAspNetProvider
{
    public class ActiveDirectoryLibrary
    {
        #region Private variables for storing configuration settings.
        internal string connectionUsername, connectionPassword;
        internal string connectionString, connectionDomain;
        internal string[] usersToIgnore, rolesToIgnore, allowedUsers, allowedRoles;
        internal Dictionary<string, string> rolesToRename;
        internal bool cacheRolesInCookie, ignoreDefaultRoles, ignoreDefaultUsers;
        #endregion

        #region Default settings
        /// <summary>
        /// Default users to ignore in output.
        /// </summary>
        private string[] defaultUsersToIgnore = new string[]
            {
                "Administrator", "TsInternetUser", "Guest", "krbtgt", "Replicate", "SERVICE", "SMSService"
            };

        /// <summary>
        /// Default groups to ignore in output.
        /// </summary>
        private string[] defaultRolesToIgnore = new string[]
            {
                "Domain Guests", "Domain Computers", "Group Policy Creator Owners", "Guests", "Users",
                "Domain Users", "Pre-Windows 2000 Compatible Access", "Exchange Domain Servers", "Schema Admins",
                "Enterprise Admins", "Domain Admins", "Cert Publishers", "Backup Operators", "Account Operators",
                "Server Operators", "Print Operators", "Replicator", "Domain Controllers", "WINS Users",
                "DnsAdmins", "DnsUpdateProxy", "DHCP Users", "DHCP Administrators", "Exchange Services",
                "Exchange Enterprise Servers", "Remote Desktop Users", "Network Configuration Operators",
                "Incoming Forest Trust Builders", "Performance Monitor Users", "Performance Log Users",
                "Windows Authorization Access Group", "Terminal Server License Servers", "Distributed COM Users",
                "Administrators", "Everybody", "RAS and IAS Servers", "MTS Trusted Impersonators",
                "MTS Impersonators", "Everyone", "LOCAL", "Authenticated Users"
            };
        #endregion

        /// <summary>
        /// Initialize library.
        /// </summary>
        /// <param name="config">Configuration settings.</param>
        public ActiveDirectoryLibrary(NameValueCollection config)
        {
            // Check to ensure configuration is specified.
            if (config == null)
            {
                throw new ArgumentNullException("No configuration specified.");
            }

            // Process connection string.
            // Get connection string.
            if (string.IsNullOrWhiteSpace(config["connectionStringName"]))
            {
                throw new ProviderException("Attribute 'connectionStringName' missing or empty.");
            }
            if (ConfigurationManager.ConnectionStrings[config["connectionStringName"]] == null)
            {
                throw new ProviderException(String.Format("Specified \"{0}\" connection string does not exist.", config["connectionStringName"]));
            }
            if (ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString.Substring(0, 7) != "LDAP://")
            {
                throw new ProviderException(String.Format("Specified \"{0}\" connection string is invalid.", config["connectionStringName"]));
            }
            this.connectionString = ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString;

            // Get connection username, password, domain.  Default to null if they don't exist.
            this.connectionUsername = string.IsNullOrWhiteSpace(config["connectionUsername"]) ? null : config["connectionUsername"];
            this.connectionPassword = string.IsNullOrWhiteSpace(config["connectionPassword"]) ? null : config["connectionPassword"];
            this.connectionDomain = string.IsNullOrWhiteSpace(config["connectionDomain"]) ? null : config["connectionDomain"];

            // Process username to remove any domain prefix.
            if (this.connectionUsername.IndexOf('\\') != -1)
            {
                this.connectionUsername = this.connectionUsername.Substring(this.connectionUsername.IndexOf('\\') + 1);
            }

            // Process users to ignore.
            this.usersToIgnore = (String.IsNullOrWhiteSpace(config["usersToIgnore"])) ? new string[] { } : config["usersToIgnore"].Split(',').Select(role => role.Trim()).ToArray<string>();

            // Process default users to ignore.
            if (!string.IsNullOrWhiteSpace(config["ignoreDefaultUsers"]) && (config["ignoreDefaultUsers"].ToLower() == "false"))
            {
                this.ignoreDefaultUsers = false;
            }
            else
            {
                this.ignoreDefaultUsers = true;
                this.usersToIgnore = this.usersToIgnore.Union(this.defaultUsersToIgnore).ToArray<string>();
            }

            // Process roles to ignore.
            this.rolesToIgnore = (String.IsNullOrWhiteSpace(config["rolesToIgnore"])) ? new string[] { } : config["rolesToIgnore"].Split(',').Select(role => role.Trim()).ToArray<string>();

            // Process default roles to ignore.
            if (!string.IsNullOrWhiteSpace(config["ignoreDefaultRoles"]) && (config["ignoreDefaultRoles"].ToLower() == "false"))
            {
                this.ignoreDefaultRoles = false;

            }
            else
            {
                this.ignoreDefaultRoles = true;
                this.rolesToIgnore = this.rolesToIgnore.Union(this.defaultRolesToIgnore).ToArray<string>();
            }

            // Process roles caching.
            if (!string.IsNullOrWhiteSpace(config["cacheRolesInCookie"]) && (config["cacheRolesInCookie"].ToLower() == "true"))
            {
                this.cacheRolesInCookie = true;
            }
            else
            {
                this.cacheRolesInCookie = false;
            }

            // Prepare allowed users and roles.
            this.allowedRoles = (String.IsNullOrWhiteSpace(config["allowedRoles"])) ? new string[] { } : config["allowedRoles"].Split(',').Select(role => role.Trim()).ToArray<string>();
            this.allowedUsers = (String.IsNullOrWhiteSpace(config["allowedUsers"])) ? new string[] { } : config["allowedUsers"].Split(',').Select(user => user.Trim()).ToArray<string>();

            // Prepare groups to rename.
            var rolesToRenameFromList = (String.IsNullOrWhiteSpace(config["rolesToRenameFrom"])) ? new string[] { } : config["rolesToRenameFrom"].Split(',').Select(role => role.Trim()).ToArray<string>();
            var rolesToRenameToList = (String.IsNullOrWhiteSpace(config["rolesToRenameTo"])) ? new string[] { } : config["rolesToRenameTo"].Split(',').Select(role => role.Trim()).ToArray<string>();

            // If renameFromList and renameToList have different numbers of elements, throw exception.
            if (rolesToRenameFromList.Count() != rolesToRenameToList.Count())
            {
                throw new ProviderException("Must be same number of groups to rename from as to.");
            }

            // Add groups to rename to dictionary.
            this.rolesToRename = new Dictionary<string, string>();
            for (int i = 0; i < rolesToRenameFromList.Count(); i++)
            {
                try
                {
                    if (!String.IsNullOrWhiteSpace(rolesToRenameFromList[i]) && !String.IsNullOrWhiteSpace(rolesToRenameToList[i]))
                    {
                        this.rolesToRename.Add(rolesToRenameFromList[i], rolesToRenameToList[i]);
                        this.rolesToRename.Add(rolesToRenameToList[i], rolesToRenameToList[i]);
                    }
                }
                catch (ArgumentException ex)
                {
                    throw new ProviderException("Role name can only be renamed once.", ex);
                }
            }

        }

        /// <summary>
        /// Determines default application name for running process.
        /// </summary>
        /// <returns>Default application name.</returns>
        internal static string GetDefaultApplicationName()
        {
            try
            {
                // Get application virtual path.
                string applicationName = HostingEnvironment.ApplicationVirtualPath;

                // If needed, try to process module name.
                if (String.IsNullOrWhiteSpace(applicationName))
                {
                    applicationName = System.Diagnostics.Process.GetCurrentProcess().MainModule.ModuleName;
                    int indexOfDot = applicationName.IndexOf('.');
                    if (indexOfDot != -1)
                    {
                        applicationName = applicationName.Remove(indexOfDot);
                    }
                }

                if (string.IsNullOrWhiteSpace(applicationName))
                {
                    return "/";
                }

                return applicationName;
            }
            catch
            {
                return "/";
            }
        }

        /// <summary>
        /// Search Active Directory.
        /// </summary>
        /// <param name="filter">Filter to use.</param>
        /// <param name="field">Field to return.</param>
        /// <returns>Array containing values from specified field.</returns>
        internal string[] SearchAD(string filter, string field)
        {
            // Initialize variables.
            string resultString = string.Empty;

            // Configure AD searcher.
            DirectorySearcher searcher = new DirectorySearcher();
            searcher.SearchRoot = new DirectoryEntry(this.connectionString);
            searcher.Filter = filter;
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.Add(field);
            searcher.PageSize = 500;

            // Get search results.
            SearchResultCollection results;
            try
            {
                results = searcher.FindAll();
            }
            catch (Exception ex)
            {
                throw new ProviderException("Could not query Active Directory.", ex);
            }

            // Iterate through search results
            foreach (SearchResult result in results)
            {
                int resultCount = result.Properties[field].Count;
                for (int i = 0; i < resultCount; i++)
                {
                    resultString += result.Properties[field][i].ToString() + "|";
                }
            }

            // Dispose of search results.
            results.Dispose();

            if (!String.IsNullOrWhiteSpace(resultString))
            {
                // Remove final separator.
                resultString = resultString.Substring(0, resultString.Length - 1);

                // Split into multiple sections.
                return resultString.Split('|');
            }
            else
            {
                // Return empty string array.
                return new string[0];
            }
        }

        /// <summary>
        /// Find users in specified role whose name matches given entry.
        /// </summary>
        /// <param name="roleName">Role to check.</param>
        /// <param name="usernameToMatch">Username to match.</param>
        /// <returns></returns>
        public string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            // Rename role.
            roleName = RenameRole(roleName);

            // Test to make sure the role exists.
            if (!RoleExists(roleName))
            {
                throw new ProviderException(String.Format("Specified role {0} does not exist.", roleName));
            }

            var allUsers = this.GetUsersInRole(roleName);

            // Find usernames that match.
            var matchingUsers = allUsers.Where(u => u.Contains(usernameToMatch));

            // Filter allowed users.
            if (this.allowedUsers != null)
            {
                matchingUsers = matchingUsers.Intersect(this.allowedUsers);

            }

            return matchingUsers.Except(this.usersToIgnore).ToArray<string>();

        }

        /// <summary>
        /// Get all roles for the defined connection string.
        /// </summary>
        /// <returns>String array of roles.</returns>
        public string[] GetAllRoles()
        {
            // Search Active Directory for groups.
            string[] roles = SearchAD("(&(objectCategory=group)(|(groupType=-2147483646)(groupType=-2147483644)(groupType=-2147483640)))", "samAccountName");

            // Iterate through to process roles.
            List<string> results = new List<string>();
            foreach (string role in roles)
            {
                results.Add(RenameRole(role));
            }

            // Filter allowed roles.
            if (this.allowedRoles != null)
            {
                results = results.Intersect(this.allowedRoles).ToList<string>();
            }

            // Filter groups to ignore. Return results.
            return results.Except(this.rolesToIgnore).ToArray<string>();
        }

        /// <summary>
        /// Gets all roles listed for a specified user.
        /// </summary>
        /// <param name="username">User to check.</param>
        /// <returns>Array listing all roles for specified user.</returns>
        public string[] GetRolesForUser(string username)
        {
            // Private variables.
            List<string> results = new List<string>();

            // See if user value has been cached.
            FormsIdentity identity;
            if ((this.cacheRolesInCookie) && (HttpContext.Current.User.Identity != null))
            {
                identity = HttpContext.Current.User.Identity as FormsIdentity;

                // See if current user is same as we're checking for.
                if ((identity != null) && (identity.Name == username))
                {
                    if (!String.IsNullOrWhiteSpace(identity.Ticket.UserData))
                    {
                        // Data has been cached.  Return data.
                        return identity.Ticket.UserData.Split(',').ToArray<string>();
                    }
                }
            }

            // Create database context.  Method varies depending on if username and password are used.
            PrincipalContext context;

            if (!String.IsNullOrWhiteSpace(this.connectionUsername) && !String.IsNullOrWhiteSpace(this.connectionPassword))
            {
                // Username and password are specified.
                context = new PrincipalContext(ContextType.Domain, this.connectionDomain, this.connectionUsername, this.connectionPassword);
            }
            else
            {
                context = new PrincipalContext(ContextType.Domain, null, this.connectionDomain);
            }

            // Try to load information for the specified user.
            try
            {
                using (UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username))
                {
                    using (var groups = user.GetAuthorizationGroups())
                    {
                        // Use group enumerator to loop because of issues with errors on sometimes-returned invalid SIDs.
                        using (var groupEnum = groups.GetEnumerator())
                        {
                            while (groupEnum.MoveNext())
                            {
                                Principal currentPrincipal = null;
                                try
                                {
                                    currentPrincipal = groupEnum.Current;

                                    results.Add(RenameRole(currentPrincipal.SamAccountName));
                                }
                                catch (PrincipalOperationException)
                                {
                                    continue;
                                }
                                finally
                                {
                                    if (currentPrincipal != null)
                                    {
                                        currentPrincipal.Dispose();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ProviderException("Could not query Active Directory.", ex);
            }

            // Dispose of context.
            context.Dispose();

            // Filter allowed roles.
            if (this.allowedRoles != null)
            {
                results = results.Intersect(this.allowedRoles).ToList<string>();
            }
            results = results.Except(this.rolesToIgnore).ToList<string>();

            // Cache data in ticket if needed.
            if ((this.cacheRolesInCookie) && (HttpContext.Current.User.Identity != null))
            {
                identity = HttpContext.Current.User.Identity as FormsIdentity;

                // See if current user is same as we're checking for.
                if ((identity != null) && (identity.Name == username))
                {
                    // They are the same.  Get ticket.
                    var oldTicket = identity.Ticket;

                    // Calculate roles data to include.
                    string ticketRoles = String.Join(",", results);

                    // Create new ticket.
                    var newTicket = new FormsAuthenticationTicket(
                        oldTicket.Version, // version
                        oldTicket.Name, // name
                        oldTicket.IssueDate, // issue date
                        oldTicket.Expiration, // expiration
                        oldTicket.IsPersistent, // persistent
                        ticketRoles             // roles data
                        );
                    string encryptedTicket = FormsAuthentication.Encrypt(newTicket);
                    var formsCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
                    HttpContext.Current.Response.Cookies.Add(formsCookie);
                }

            }

            // Filter groups to ignore. Return results.
            return results.Except(this.rolesToIgnore).ToArray<string>();
        }

        /// <summary>
        /// Get users in specified role.
        /// </summary>
        /// <param name="roleName">Role to check.</param>
        /// <returns>Array of users.</returns>
        public string[] GetUsersInRole(string roleName)
        {
            // Rename role.
            roleName = RenameRole(roleName);

            // Test to make sure the role exists.
            if (!RoleExists(roleName))
            {
                throw new ProviderException(String.Format("Specified role {0} does not exist.", roleName));
            }

            // Private variables.
            List<string> results = new List<string>();

            // Create database context.  Method varies depending on if username and password are used.
            PrincipalContext context;

            if (!String.IsNullOrWhiteSpace(this.connectionUsername) && !String.IsNullOrWhiteSpace(this.connectionPassword))
            {
                // Username and password are specified.
                context = new PrincipalContext(ContextType.Domain, this.connectionDomain, this.connectionUsername, this.connectionPassword);
            }
            else
            {
                context = new PrincipalContext(ContextType.Domain, null, this.connectionDomain);
            }

            // Try to load information for the specified role.
            try
            {
                using (GroupPrincipal group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, roleName))
                {
                    using (var users = group.GetMembers())
                    {
                        // Use group enumerator to loop because of issues with errors on sometimes-returned invalid SIDs.
                        using (var userEnum = users.GetEnumerator())
                        {
                            while (userEnum.MoveNext())
                            {
                                Principal currentPrincipal = null;
                                try
                                {
                                    currentPrincipal = userEnum.Current;

                                    // Add current user to list.
                                    results.Add(currentPrincipal.SamAccountName);
                                }
                                catch (PrincipalOperationException)
                                {
                                    continue;
                                }
                                finally
                                {
                                    if (currentPrincipal != null)
                                    {
                                        currentPrincipal.Dispose();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ProviderException("Could not query Active Directory.", ex);
            }

            // Dispose of context.
            context.Dispose();

            // Filter allowed users.
            if (this.allowedUsers != null)
            {
                results = results.Intersect(this.allowedUsers).ToList<string>();
            }

            // Filter users to ignore. Return results.
            return results.Except(this.usersToIgnore).ToArray<string>();
        }

        /// <summary>
        /// Determines if user is a member of the specified role.
        /// </summary>
        /// <param name="username">Username to check.</param>
        /// <param name="roleName">Role name to check.</param>
        /// <returns>True/false</returns>
        public bool IsUserInRole(string username, string roleName)
        {
            // Rename role.
            roleName = RenameRole(roleName);

            // Get list of roles for specified user.
            var userRoles = GetRolesForUser(username);

            // Check if role list contains the specified role.
            return userRoles.Contains(roleName);
        }

        /// <summary>
        /// Determines if the specified role exists.
        /// </summary>
        /// <param name="roleName">Role to check.</param>
        /// <returns>True/false</returns>
        public bool RoleExists(string roleName)
        {
            // Rename role.
            roleName = RenameRole(roleName);

            // Get list of all roles.
            var allRoles = GetAllRoles();


            // CHeck if role list contains specified role.
            return allRoles.Contains(roleName);
        }

        /// <summary>
        /// Converts role names to/from old form.
        /// </summary>
        /// <param name="roleName">Role name to convert.</param>
        /// <returns>Converted role name.</returns>
        private string RenameRole(string roleName)
        {
            if (this.rolesToRename.Keys.Contains(roleName))
            {
                // Return renamed name.
                return this.rolesToRename[roleName];
            }
            else
            {
                // Return original name.
                return roleName;
            }
        }
    }
}
