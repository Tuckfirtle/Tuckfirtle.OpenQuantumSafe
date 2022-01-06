// Copyright (C) 2022, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public class MechanismNotEnabledException : MechanismException
    {
        public MechanismNotEnabledException(string requestMechanism) : base(requestMechanism, $"{requestMechanism} is not enabled.")
        {
        }
    }
}