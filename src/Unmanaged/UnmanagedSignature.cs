// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

using System;
using System.Runtime.InteropServices;

namespace Tuckfirtle.OpenQuantumSafe.Unmanaged
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal readonly struct UnmanagedSignature
    {
        /// <summary>
        /// Printable string representing the name of the signature scheme.
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
        /// Whether the signature offers EUF-CMA security (TRUE) or not (FALSE).
        /// </summary>
        [MarshalAs(UnmanagedType.U1)]
        public readonly bool IsEufCma;

        /// <summary>
        /// The (maximum) length, in bytes, of public keys for this signature scheme.
        /// </summary>
        public readonly UIntPtr PublicKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of secret keys for this signature scheme.
        /// </summary>
        public readonly UIntPtr SecretKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of signatures for this signature scheme.
        /// </summary>
        public readonly UIntPtr SignatureLength;

        public readonly KeypairDelegate GenerateKeypair;

        public readonly SignDelegate Sign;

        public readonly VerifyDelegate Verify;

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status KeypairDelegate(byte[] publicKey, byte[] secretKey);

        /// <summary>
        /// Signature generation algorithm.
        /// </summary>
        /// <param name="signature">The signature on the message represented as a byte string.</param>
        /// <param name="signatureLen">The length of the signature.</param>
        /// <param name="message">The message to sign represented as a byte string.</param>
        /// <param name="messageLen">The length of the message to sign.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status SignDelegate(byte[] signature, ref UIntPtr signatureLen, byte[] message, UIntPtr messageLen, byte[] secretKey);

        /// <summary>
        /// Signature verification algorithm.
        /// </summary>
        /// <param name="message">The message represented as a byte string.</param>
        /// <param name="messageLen">The length of the message.</param>
        /// <param name="signature">The signature on the message represented as a byte string.</param>
        /// <param name="signatureLen">The length of the signature.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public delegate Status VerifyDelegate(byte[] message, UIntPtr messageLen, byte[] signature, UIntPtr signatureLen, byte[] publicKey);
    }
}