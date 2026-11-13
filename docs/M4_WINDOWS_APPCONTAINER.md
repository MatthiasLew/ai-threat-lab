# M4 Windows AppContainer probe

The native fixture creates a unique capability-free AppContainer profile.
The host grants the profile read access to synthetic input and sets a low
integrity label and modify ACL on scratch. Process creation attaches the
Job Object before resuming the payload. The launcher disables handle
inheritance and receives a restricted environment. The fixture checks
the token, the host canary handle, read/write boundaries, local TCP/UDP
delivery, child denial, timeout, and supervisor death. It deletes its
own profile. The test uses MSVC x64 and the Windows SDK.

Windows symlink access is exercised when the host permits symlink creation.
Junction denial and directory replacement tests are required. The directory
replacement test exercises the existing pinned read scope independently of
AppContainer launch. Future production work must keep that protection from
approval through process creation. AppContainer can access Windows resources
allowed by their existing ACLs. Scratch capacity, crash recovery of profile
and filesystem artifacts, externally scoped network enforcement, and
production runtime identity remain open. No firewall rule is changed.

The API requirements and network model follow the
[Microsoft AppContainer launch guidance](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
and [Windows loopback guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall).
