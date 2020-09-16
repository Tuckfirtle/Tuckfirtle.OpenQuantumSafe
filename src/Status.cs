// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

namespace Tuckfirtle.OpenQuantumSafe
{
    public enum Status
    {
        /// <summary>
        /// Used to indicate that some undefined error occurred.
        /// </summary>
        Error = -1,

        /// <summary>
        /// Used to indicate successful return from function.
        /// </summary>
        Success = 0,

        /// <summary>
        /// Used to indicate failures in external libraries (e.g., OpenSSL).
        /// </summary>
        ExternalLibErrorOpenSsl = 50
    }
}