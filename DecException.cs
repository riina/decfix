using System;

namespace decfix;

internal class DecException : Exception
{
    internal DecException(string message) : base(message)
    {
    }
}
