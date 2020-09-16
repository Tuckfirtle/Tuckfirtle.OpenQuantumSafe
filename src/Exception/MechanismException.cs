// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public abstract class MechanismException : System.Exception
    {
        public string RequestedMechanism { get; }

        protected MechanismException(string requestedMechanism, string message) : base(message)
        {
            RequestedMechanism = requestedMechanism;
        }
    }
}