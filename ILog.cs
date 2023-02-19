namespace decfix;

internal interface ILog
{
    void Log(string message);
    void LogWarning(string message);
    void LogError(string message);
}
