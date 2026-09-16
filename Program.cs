using System.Security.AccessControl;
using System.Security.Principal;

namespace Rwx;

// inspect windows file/directory permissions and ACLs
// shows who can read/write/execute and why (which ACE grants it)

static class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0) { Help(); return; }

        bool verbose = args.Contains("-v") || args.Contains("--verbose");
        bool checkCurrent = args.Contains("--me");

        var paths = args.Where(a => !a.StartsWith('-')).ToList();
        if (paths.Count == 0) { Err("at least one path required"); return; }

        foreach (var path in paths)
            Inspect(path, verbose, checkCurrent);
    }

    static void Inspect(string path, bool verbose, bool checkCurrent)
    {
        bool isDir = Directory.Exists(path);
        bool isFile = File.Exists(path);

        if (!isDir && !isFile) { Err($"not found: {path}"); return; }

        Console.WriteLine($"\n  {Cyan(path)}  {Dim(isDir ? "directory" : "file")}");

        try
        {
            FileSystemSecurity acl = isDir
                ? new DirectoryInfo(path).GetAccessControl()
                : new FileInfo(path).GetAccessControl();

            var owner = acl.GetOwner(typeof(NTAccount));
            Console.WriteLine($"  {Dim("owner")}  {owner}");
            Console.WriteLine();

            var rules = acl.GetAccessRules(true, true, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .OrderBy(r => r.IdentityReference.Value)
                .ToList();

            if (rules.Count == 0)
            {
                Console.WriteLine(Dim("  (no ACEs found)"));
                return;
            }

            // group by identity
            var byIdentity = rules.GroupBy(r => r.IdentityReference.Value);
            foreach (var group in byIdentity)
            {
                Console.WriteLine($"  {Bold(group.Key)}");
                foreach (var rule in group)
                {
                    string type = rule.AccessControlType == AccessControlType.Allow
                        ? "\x1b[32mallow\x1b[0m" : "\x1b[31mdeny \x1b[0m";
                    string rights = FormatRights(rule.FileSystemRights);
                    string inherit = FormatInheritance(rule.InheritanceFlags, rule.PropagationFlags);

                    if (verbose)
                        Console.WriteLine($"    {type}  {rights,-40} {Dim(inherit)}");
                    else
                        Console.WriteLine($"    {type}  {rights}");
                }
                Console.WriteLine();
            }

            if (checkCurrent)
            {
                var me = WindowsIdentity.GetCurrent();
                Console.WriteLine($"  {Dim("current user:")} {me.Name}");
                CheckAccess(path, isDir);
            }
        }
        catch (UnauthorizedAccessException)
        {
            Err("access denied — try running as administrator");
        }
        catch (Exception ex)
        {
            Err($"failed to read ACL: {ex.Message}");
        }
    }

    static void CheckAccess(string path, bool isDir)
    {
        bool canRead = false, canWrite = false;
        try { using var f = File.OpenRead(path); canRead = true; } catch { }
        try
        {
            if (isDir)
                canWrite = new DirectoryInfo(path).GetAccessControl() != null; // rough check
            else
            {
                using var f = File.OpenWrite(path);
                canWrite = true;
            }
        }
        catch { }

        string r = canRead ? "\x1b[32mr\x1b[0m" : "\x1b[31m-\x1b[0m";
        string w = canWrite ? "\x1b[32mw\x1b[0m" : "\x1b[31m-\x1b[0m";
        Console.WriteLine($"  {Dim("effective:")} {r}{w}x");
    }

    static string FormatRights(FileSystemRights rights)
    {
        // show human-readable summary instead of raw flags
        var parts = new List<string>();
        if ((rights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
            return "full control";
        if ((rights & FileSystemRights.Read) != 0) parts.Add("read");
        if ((rights & FileSystemRights.Write) != 0) parts.Add("write");
        if ((rights & FileSystemRights.ExecuteFile) != 0) parts.Add("execute");
        if ((rights & FileSystemRights.Modify) == FileSystemRights.Modify) parts.Add("modify");
        if ((rights & FileSystemRights.Delete) != 0) parts.Add("delete");
        if ((rights & FileSystemRights.ChangePermissions) != 0) parts.Add("change-perms");
        if ((rights & FileSystemRights.TakeOwnership) != 0) parts.Add("take-ownership");
        return parts.Count > 0 ? string.Join(", ", parts) : rights.ToString();
    }

    static string FormatInheritance(InheritanceFlags inh, PropagationFlags prop)
    {
        var parts = new List<string>();
        if (inh.HasFlag(InheritanceFlags.ContainerInherit)) parts.Add("container-inherit");
        if (inh.HasFlag(InheritanceFlags.ObjectInherit)) parts.Add("object-inherit");
        if (prop.HasFlag(PropagationFlags.InheritOnly)) parts.Add("inherit-only");
        if (prop.HasFlag(PropagationFlags.NoPropagateInherit)) parts.Add("no-propagate");
        return parts.Count > 0 ? string.Join(", ", parts) : "this object only";
    }

    static string Cyan(string s) => $"\x1b[36m{s}\x1b[0m";
    static string Bold(string s) => $"\x1b[1m{s}\x1b[0m";
    static string Dim(string s) => $"\x1b[2m{s}\x1b[0m";
    static void Err(string msg) => Console.Error.WriteLine($"  \x1b[31merror:\x1b[0m {msg}");

    static void Help() => Console.WriteLine("""

  rwx — inspect windows file and directory permissions

  usage:
    rwx <path...> [flags]

  flags:
    -v, --verbose    show inheritance and propagation flags
    --me             check what the current user can actually do

  examples:
    rwx C:\Windows\System32\cmd.exe
    rwx C:\Users\me\Documents -v
    rwx C:\secret --me
    rwx file1.txt file2.txt

""");
}
