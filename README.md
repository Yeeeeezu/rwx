# rwx

inspect windows file permissions and ACLs. see who has access and what kind.

```
rwx <path...> [flags]
```

---

## example

```
> rwx C:\Windows\System32\cmd.exe

  C:\Windows\System32\cmd.exe  file
  owner  NT SERVICE\TrustedInstaller

  NT SERVICE\TrustedInstaller
    allow  full control

  NT AUTHORITY\SYSTEM
    allow  read, execute

  BUILTIN\Administrators
    allow  read, execute

  BUILTIN\Users
    allow  read, execute
```

## flags

| flag | description |
|------|-------------|
| `-v, --verbose` | show inheritance and propagation flags |
| `--me` | also check effective access for the current user |

## usage

```sh
rwx C:\file.txt
rwx C:\some\dir -v
rwx C:\secret --me
rwx file1 file2 file3      # multiple paths at once
```

## build

```
dotnet build -c Release
```

.NET 8+, windows only. some paths require admin to read ACLs.

## testing

built and ran against `C:\Windows\System32\cmd.exe`. correct owner (TrustedInstaller), correct ACEs for SYSTEM/Administrators/Users all confirmed. identity grouping and right formatting verified.

**not tested:** paths with deny ACEs, complex inheritance chains, network shares, junction points.

## license

MIT
