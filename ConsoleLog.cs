namespace decfix;

internal class ConsoleLog : ILog
{
    public void Log(string message) => Util.PrintMessage(message);

    public void LogWarning(string message) => Util.PrintWarningMessage(message);

    public void LogError(string message) => Util.PrintErrorMessage(message);
}
