# AdAspNetProvider
This assembly includes ASP.NET-compatible MembershipProvider and RoleProvider providers.

Special features of these providers include:
- Integrated server-based caching of user's roles
- Ability to dynamically rename roles so you're not tied to Active Directory group names
- Ability to deny access in MembershipProvider based on group/role membership

## What's inside
This project includes two providers:
- ActiveDirectoryMembershipProvider: Membership provider that supports user authentication against Active Directory
- ActiveDirectoryRoleProvider: Role provider that supports uses Active Directory group membership for roles

## System requirements
1. NET Framework 4

## NuGet availability
This project is available on [NuGet](https://www.nuget.org/packages/AdAspNetProvider)

## Related projects
To use `AdAspNetProvider.ActiveDirectoryMembershipProvider` with Umbraco 7.3.1+, also use [UmbBackofficeMembershipProvider](https://github.com/Bitmapped/UmbBackofficeMembershipProvider).

## Usage instructions
### Getting started
1. Add **AdAspNetProvider.dll** as a reference in your project.
2. Configure the providers in **web.config** for our project.
  - Sample configuration:
  ```
  <membership defaultProvider="AdAspNetMembershipProvider">
    <providers>
      <add name="AdAspNetMembershipProvider" type="AdAspNetProvider.ActiveDirectoryMembershipProvider" connectionStringName="MyConnectionString" attributeMapUsername="sAMAccountName" connectionDomain="domain.com" connectionUsername="username" connectionPassword="password" ignoreServerIpAddresses="10.0.0.5" />
    </providers>
  </membership>
  <roleManager enabled="true" defaultProvider="AdAspNetRoleProvider">
    <providers>
      <add name="AdAspNetRoleProvider" type="AdAspNetProvider.ActiveDirectoryRoleProvider" connectionStringName="MyConnectionString" connectionDomain="domain.com" connectionUsername="username" connectionPassword="password" allowedRoles="Business-Administration,Business-Instructors" rolesToRenameFrom="Company-Administration,Company-Instructors" rolesToRenameTo="Business-Administration,Business-Instructors" />
    </providers>
  </roleManager>
  ```
  
  - Supported options for both membership and role providers:
    - `connectionStringName` - name of connection string in your **web.config** or **application.config** file
    - `connectionUsername` - username of account in Active Directory to use with this application
    - `connectionPassword` - password of account in Active Directory to use with this application
    - `usersToIgnore` - comma-separated list of blacklisted users that should be ignored (default is empty list)
    - `rolesToIgnore` - comma-separated list of blacklisted roles (Active Directory groups) that should be ignored (default is empty list)
    - `ignoreDefaultUsers` - true/false if [common user accounts](https://gist.github.com/Bitmapped/e532454f6a64ef52ca7e) should be ignored (default true)
    - `ignoreDefaultRoles` - true/false if [common roles](https://gist.github.com/Bitmapped/e532454f6a64ef52ca7e) should be ignored (default true)
    - `rolesToRenameFrom` - ordered comma-separated list of roles you wish to rename; if role is not in list, it's not renamed (default is empty list)
    - `rolesToRenameTo` - ordered comma-separated list of new names for roles being renamed (default is empty list)
    - `allowedUsers` - comma-separated list of whitelisted users that should be treated as only valid users (default is empty list, which does not restrict users)
    - `allowedRoles` - comma-separated list of whitelisted roles that should be treated as only valid roles (default is empty list, which does not restrict roles)
    - `cacheDurationInMinutes` - for caching of roles and DNS lookups for Active Directory controllers
    - `attributeMapUsername` - to control format of listed role and user names as `sAMAccountName` or `userPrincipalName`
    - `maxAttempts` - maximum number of times to attempt AD operation before failing
    - `maxServerFailures` - maximum number of times AD server can fail before removed from current cached list of controllers
    - `enableSearchMethods` - true/false if methods for searching for users and groups should be enabled
    - `ignoreServerIpAddresses` - comma-separated list of server IP addresses that should be ignored if returned by a DNS lookup
    - `silentlyIgnoreNotSupported` - true/false if not-supported methods should return generic values rather than throwing NotSupportedException

- Supported options for role providers only:
  - `recursiveRoleMembership` - true/false if user should be considered member of any roles (Active Directory groups) that include roles they are already a member of (default false)

### Using with Umbraco
AdAspNetProvider can be used to provide public members and member groups functionality in Umbraco. It can also be used to provide backend users functionality.

When using ActiveDirectoryRoleProvider in Umbraco to handle public member groups, you must set the `enableSearchMethods` property to true in your connection string.
