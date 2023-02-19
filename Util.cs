using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace decfix;

internal static class Util
{
    internal static readonly Dictionary<DecType, Func<string, int>> s_hashFunctions;
    internal static readonly Dictionary<DecType, int> s_emptyHashes;
    private static readonly Regex s_passwordRegex = new("^[a-zA-Z0-9.-]*$");

    static Util()
    {
        s_hashFunctions = new Dictionary<DecType, Func<string, int>> { { DecType.Windows, HashNf }, { DecType.Mono, HashM } };
        s_emptyHashes = new Dictionary<DecType, int> { { DecType.Windows, HashNf("") }, { DecType.Mono, HashM("") } };
    }

    private static int HashNf(string str)
    {
        int v1 = 0x15051505, v2 = v1;
        int length = str.Length;
        int i = 0;
        while (length > 2)
        {
            v1 = ((v1 << 5) + v1 + (v1 >> 27)) ^ (str[i] + (str[i + 1] << 16));
            v2 = ((v2 << 5) + v2 + (v2 >> 27)) ^ (str[i + 2] + ((length > 3 ? str[i + 3] : 0) << 16));
            i += 4;
            length -= 4;
        }
        if (length > 0)
            v1 = ((v1 << 5) + v1 + (v1 >> 27)) ^ (str[i] + ((length > 1 ? str[i + 1] : 0) << 16));
        return (ushort)(v1 + v2 * 0x5D588B65);
    }

    private static int HashM(string str)
    {
        int v = 0;
        for (int i = 0; i < str.Length; i++)
            v = (v << 5) - v + str[i];
        return (ushort)v;
    }

    internal static string GeneratePath(string directory, string baseFile, DecType type)
    {
        return Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(baseFile)}_decfix_{type.GetDisplayName()}{Path.GetExtension(baseFile)}");
    }

    internal static Dictionary<int, HashSet<HashEntry>> GenerateHashDictionary(IReadOnlyCollection<string> passwords)
    {
        Dictionary<int, HashSet<HashEntry>> target = new();
        foreach (DecType type in new[] { DecType.Windows, DecType.Mono })
        foreach (string password in passwords)
        {
            int hash = s_hashFunctions[type](password);
            if (!target.ContainsKey(hash))
                target.Add(hash, new HashSet<HashEntry>());
            target[hash].Add(new HashEntry(type, password));
        }
        return target;
    }

    internal static bool Analyze(string name, string[] lines, Dictionary<int, HashSet<HashEntry>> dict, ILog log, [NotNullWhen(true)] out DecFile? decfile, out DecType? originType, out string? originPassword)
    {
        originType = null;
        originPassword = null;
        decfile = null;
        DecHeader header = DecryptHeader(lines, s_emptyHashes[DecType.Windows]);
        if (string.IsNullOrEmpty(header.Key))
            throw new DecException("No constphrase specified in DEC header");
        int hash = int.Parse(header.Key.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0], CultureInfo.InvariantCulture) - 158485;
        if (dict.TryGetValue(hash, out var set))
        {
            if (set.Count != 1)
            {
                StringBuilder sb = new();
                foreach ((DecType decType, string? password) in set)
                    sb.Append(decType.ToString()).Append(':').Append(password).Append(';');
                log.LogWarning($"Collision, {set.Count} passwords for {name}. Choosing one arbitrarily. (from {sb})");
            }
            var hashEntry = set.First();
            if (TryDecrypt(lines, hash, s_emptyHashes[hashEntry.Type], out decfile))
            {
                originType = hashEntry.Type;
                originPassword = hashEntry.Password;
                return true;
            }
            return false;
        }
        log.LogWarning($"Unknown password detected for {name}, falling back to heuristic header check.");
        foreach (DecType type in new[] { DecType.Windows, DecType.Mono })
        {
            string str = DecryptString(lines[0].Split("::")[2], s_emptyHashes[type]);
            if (!s_passwordRegex.IsMatch(str)) continue;
            originType = type;
            return TryDecrypt(lines, hash, s_emptyHashes[type], out decfile);
        }
        log.LogWarning("Heuristic header check failed, defaulting to Windows.");
        return TryDecrypt(lines, hash, s_emptyHashes[DecType.Windows], out decfile);
    }

    private static string EncryptString(string data, int hash)
    {
        if (string.IsNullOrEmpty(data))
            return "";
        StringBuilder sb = new();
        sb.Append(data[0] * 0x71E + 0x7FFF + hash);
        for (int i = 1; i < data.Length; i++)
            sb.Append(' ').Append(data[i] * 0x71E + 0x7FFF + hash);
        return sb.ToString();
    }

    internal static string Encrypt(string data, string header, string signature, string? extension, int hash, int empty)
    {
        StringBuilder sb = new();
        string head = "#DEC_ENC::"
                      + EncryptString(header, empty) + "::"
                      + EncryptString(signature, empty) + "::"
                      + EncryptString("ENCODED", hash);
        if (extension != null)
            head += "::" + EncryptString(extension, empty);
        sb.Append(head).Append('\n').Append(EncryptString(data, hash));
        return sb.ToString();
    }

    private static bool TryDecrypt(string[] lines, int hash, int empty, [NotNullWhen(true)] out DecFile? file)
    {
        if (lines.Length != 2)
            throw new DecException("Invalid section count " + lines.Length + " (should be 2, header and body)");
        string[] head = lines[0].Split("::");
        if (head.Length != 4 && head.Length != 5)
            throw new DecException("Invalid head array length " + head.Length + " (should be 4 or 5)");
        string encoded = DecryptString(head[3], hash);
        if (encoded == "ENCODED")
        {
            file = new DecFile(DecryptHeaderFromArr(head, empty), DecryptString(lines[1], hash));
            return true;
        }
        file = null;
        return false;
    }

    internal static DecHeader DecryptHeader(string[] lines, int empty)
    {
        if (lines.Length != 2)
            throw new DecException("Invalid section count " + lines.Length + " (should be 2, header and body)");
        string[] head = lines[0].Split("::");
        return DecryptHeaderFromArr(head, empty);
    }

    private static DecHeader DecryptHeaderFromArr(string[] head, int empty)
    {
        if (head.Length != 4 && head.Length != 5)
            throw new DecException("Invalid head array length " + head.Length + " (should be 4 or 5)");
        DecHeader target = new(
            DecryptString(head[1], empty),
            DecryptString(head[2], empty),
            head[3],
            head.Length == 5 ? DecryptString(head[4], empty) : null);
        return target;
    }

    private static string DecryptString(string data, int hash)
    {
        if (string.IsNullOrEmpty(data))
            return "";
        StringBuilder sb = new();
        string[] a = data.Split(' ');
        foreach (string s in a)
        {
            if (int.TryParse(s, out int v))
            {
                v -= 0x7FFF + hash;
                v /= 0x71E;
                sb.Append((char)v);
            }
            else
                throw new DecException($"Invalid encrypted value {s}");
        }
        return sb.ToString();
    }

    internal static string GetDisplayName(this DecType decType) => decType switch
    {
        DecType.Windows => "windows",
        DecType.Mono => "mono",
        _ => throw new ArgumentOutOfRangeException(nameof(decType), decType, null)
    };

    internal static void PrintMessage(string message)
    {
        Console.Out.WriteLine(message);
    }

    internal static void PrintExceptionMessage(Exception e)
    {
        PrintErrorMessage(e.Message);
    }

    internal static void PrintErrorMessage(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine(message);
        Console.ResetColor();
    }

    internal static void PrintWarningMessage(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Error.WriteLine(message);
        Console.ResetColor();
    }
}
