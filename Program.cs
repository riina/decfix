using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.XPath;
using decfix;

// For future reference, hn is appid 365450
Argument<FileInfo> saveFileArg = new("save-file", "Save file to create patched versions of");
Option<string> passwordFileOption = new(new[] { "-p", "--password-file" }, "Password file (containing JSON array of strings)");
Option<string> outputDirectoryOption = new(new[] { "-o", "--output-directory" }, "Directory to output");
var rootCommand = new RootCommand("Patch hacknet save file") { saveFileArg, passwordFileOption, outputDirectoryOption };
rootCommand.SetHandler(ProcessAsync);
return rootCommand.Invoke(args);

async Task<int> ProcessAsync(InvocationContext invocationContext)
{
    var log = new ConsoleLog();
    List<string> defaultPasswords = new()
    {
        "",
        "19474-217316293",
        "dx122DX",
        "84833mmn1",
        "DANGER",
        "Obi-Wan",
        "ax229msjA",
        "beepbeep",
        "decryptionPassword",
        "divingsparrow",
        "dleatrou",
        "password",
        "quinnoq",
        "test",
        "yuna"
    };
    char[] separators = { '\r', '\n' };
    FileInfo saveFile = invocationContext.ParseResult.GetValueForArgument(saveFileArg);
    string? outputDirectory = invocationContext.ParseResult.HasOption(outputDirectoryOption) ? invocationContext.ParseResult.GetValueForOption(outputDirectoryOption) : null;
    string? passwordFile = invocationContext.ParseResult.HasOption(passwordFileOption) ? invocationContext.ParseResult.GetValueForOption(passwordFileOption) : null;
    if (!saveFile.Exists)
    {
        log.LogError($"File {saveFile} does not exist.");
        Environment.Exit(118);
    }
    if (outputDirectory == null)
    {
        outputDirectory = saveFile.DirectoryName!;
    }
    Directory.CreateDirectory(outputDirectory);
    List<string> passwords = new(defaultPasswords);
    if (passwordFile != null)
    {
        if (!File.Exists(passwordFile))
        {
            Util.PrintErrorMessage($"File {passwordFile} does not exist.");
            return 119;
        }
        await using FileStream fs = new(passwordFile, FileMode.Open, FileAccess.Read);
        string[]? filePasswords = await JsonSerializer.DeserializeAsync(fs, SourceGenerationContext.Default.StringArray);
        if (filePasswords == null)
        {
            Util.PrintWarningMessage($"File {passwordFile} doesn't contain password array. Ignoring.");
        }
        else
        {
            passwords.AddRange(passwords);
        }
    }
    Dictionary<int, HashSet<HashEntry>> dict = Util.GenerateHashDictionary(passwords);
    XmlDocument document = new() { PreserveWhitespace = true };
    byte[] buf = File.ReadAllBytes(saveFile.FullName);
    foreach (DecType decType in new[] { DecType.Windows, DecType.Mono })
    {
        string decTypeName = decType.GetDisplayName();
        log.Log($"-- Processing for {decTypeName} output");
        MemoryStream ms = new(buf, false);
        document.Load(ms);
        XPathNavigator navigator = document.CreateNavigator()!;
        bool changed = false;
        foreach (XPathNavigator n in navigator.Select("//file"))
        {
            string fileData = n.Value;
            int loc = fileData.IndexOf("#DEC_ENC::", StringComparison.Ordinal);
            if (loc == -1)
                continue;
            string oname = n.GetAttribute("name", "");
            string[] data = fileData[loc..].Split(separators, StringSplitOptions.RemoveEmptyEntries);
            if (data.Length != 2)
                continue;
            string? tvalue;
            try
            {
                if (!Util.Analyze(oname, data, dict, log, out DecFile? decfile, out DecType? originType, out string? originPassword))
                    throw new DecException("DEC file not valid, parsing failed");
                string originTypeName = originType?.GetDisplayName() ?? "<unknown platform>";
                if (originPassword != null)
                {
                    DecHeader header = decfile.Header;
                    // only skip if we already have known / usable pw. otherwise dump the content
                    if (originType == decType)
                    {
                        log.Log($"Skipped {originTypeName} file {oname} (same platform)");
                        continue;
                    }
                    tvalue = Util.Encrypt(decfile.Message, header.Header, header.Signature, header.Extension, Util.s_hashFunctions[decType](originPassword), Util.s_emptyHashes[decType]);
                    log.Log($"Re-encoded {originTypeName} file {oname}");
                }
                else
                {
                    DecHeader header = decfile.Header;
                    tvalue = $"Header:\n{header.Header}\nIP:\n{header.Signature}\n";
                    if (header.Extension != null)
                        tvalue += $"Extension:\n{header.Extension}";
                    tvalue += $"Key:\n{header.Key}";
                    tvalue += $"\n{decfile.Message}";
                    log.Log($"No password for {originTypeName} file {oname} - dumped fallback");
                }
            }
            catch (DecException e)
            {
                log.LogError($"Error for file {oname}\nData:\n{fileData}\nMessage: {e.Message}");
                return 3;
            }
            n.SetValue(fileData[..loc] + tvalue);
            changed = true;
        }
        string targetPath = Util.GeneratePath(outputDirectory, saveFile.FullName, decType);
        if (changed)
        {
            log.Log($">> Saving {decTypeName} file to {targetPath}");
            document.Save(targetPath);
        }
        else
        {
            log.Log($"Skipping write of {decTypeName} file (no changes needed)");
        }
    }
    return 0;
}
