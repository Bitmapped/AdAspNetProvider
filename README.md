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
To use `AdAspNetProvider.ActiveDirectoryMembershipProvider` with Umbraco 7.3.1+, also use [UmbBackOfficeAdAspNetProvider](https://umbbackofficeadaspnetprovider.codeplex.com/).

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
  
  - Supported options:
    - `connectionStringName`
    - `connectionUsername`
    - `connectionPassword`
    - `usersToIgnore`
    - `rolesToIgnore`
    - `ignoreDefaultUsers`
    - `ignoreDefaultRoles`
    - `rolesToRenameFrom`
    - `rolesToRenameTo`
    - `allowedUsers`
    - `allowedRoles`
    - `cacheDurationInMinutes` (for caching of roles and DNS lookups for Active Directory controllers)
    - `attributeMapUsername` (to control format of listed role and user names)
    - `maxAttempts` (maximum number of times to attempt AD operation before failing)
    - `maxServerFailures` (maximum number of times AD server can fail before removed from current cached list of controllers)
    - `enableSearchMethods` (true/false if methods for searching for users and groups should be enabled)
    - `ignoreServerIpAddresses` (comma-delimited listing of server IP addresses that should be ignored if returned by a DNS lookup)
    - `silentlyIgnoreNotSupported` (true/false if not-supported methods should return generic values rather than throwing NotSupportedException)
