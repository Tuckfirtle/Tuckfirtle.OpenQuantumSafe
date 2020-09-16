// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

using System;
using System.Runtime.InteropServices;

namespace Tuckfirtle.OpenQuantumSafe.Unmanaged
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal readonly struct UnmanagedKeyEncapsulationMechanism
    {
        /// <summary>
        /// Printable string representing the name of the key encapsulation mechanism.
        /// </summary>
        public readonly string MethodName;

        /// <summary>
        /// Printable string representing the version of the cryptographic algorithm.
        /// </summary>
        public readonly string Version;

        /// <summary>
        /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
        /// </summary>
        public readonly byte ClaimedNistLevel;

        /// <summary>
        /// Whether the KEM offers IND-CCA security (TRUE) or IND-CPA security (FALSE).
        /// </summary>
        [MarshalAs(UnmanagedType.I1)]
        public readonly bool IsIndCca;

        /// <summary>
        /// The (maximum) length, in bytes, of public keys for this KEM.
        /// </summary>
        public readonly UIntPtr PublicKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of secret keys for this KEM.
        /// </summary>
        public readonly UIntPtr SecretKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of ciphertexts for this KEM.
        /// </summary>
        public readonly UIntPtr CiphertextLength;

        /// <summary>
        /// The (maximum) length, in bytes, of shared secrets for this KEM.
        /// </summary>
        public readonly UIntPtr SharedSecretLength;

        public readonly KeypairDelegate GenerateKeypair;

        public readonly EncapsulationDelegate Encapsulation;

        public readonly DecapsulationDelegate Decapsulation;

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status KeypairDelegate(byte[] publicKey, byte[] secretKey);

        /// <summary>
        /// Encapsulation algorithm.
        /// </summary>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status EncapsulationDelegate(byte[] ciphertext, byte[] sharedSecret, byte[] publicKey);

        /// <summary>
        /// Decapsulation algorithm.
        /// </summary>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status DecapsulationDelegate(byte[] sharedSecret, byte[] ciphertext, byte[] secretKey);
    }
}