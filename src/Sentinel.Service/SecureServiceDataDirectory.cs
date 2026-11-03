using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Service;

internal static class SecureServiceDataDirectory
{
    public static string GetPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel AI Service");

    public static DirectorySecurity CreateDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null));
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return security;
    }

    public static bool ValidateDirectorySecurity()
        => IsExpectedSecurity(CreateDirectorySecurity());

    public static void Prepare(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var info = new DirectoryInfo(fullPath);
        // Apply the restrictive descriptor as part of creation so there is no
        // window in which a newly created ProgramData directory has a broad ACL.
        info.Create(CreateDirectorySecurity());
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Katalog danych usługi nie może być punktem ponownej analizy.");
        var security = info.GetAccessControl(AccessControlSections.Access);
        if (!IsExpectedSecurity(security))
            throw new UnauthorizedAccessException("Katalog danych usługi ma nieoczekiwane uprawnienia.");
    }

    private static void AddFullControl(DirectorySecurity security, SecurityIdentifier sid) =>
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

    private static bool IsExpectedSecurity(DirectorySecurity security)
    {
        if (!security.AreAccessRulesProtected) return false;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>().ToArray();
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
        };
        return rules.Length == expected.Count && rules.All(rule =>
            rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == FileSystemRights.FullControl &&
            rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
            rule.PropagationFlags == PropagationFlags.None && rule.IdentityReference is SecurityIdentifier sid && expected.Remove(sid.Value)) &&
            expected.Count == 0;
    }
}
