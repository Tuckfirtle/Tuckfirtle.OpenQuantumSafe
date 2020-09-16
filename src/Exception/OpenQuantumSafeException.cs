// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public class OpenQuantumSafeException : System.Exception
    {
        public Status Status { get; }

        public OpenQuantumSafeException(string message) : base(message)
        {
        }

        public OpenQuantumSafeException(Status status) : base("Open quantum safe library has encounter an error.")
        {
            Status = status;
        }
    }
}