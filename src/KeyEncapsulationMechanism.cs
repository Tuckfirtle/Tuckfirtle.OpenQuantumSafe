// Copyright (C) 2022, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class KeyEncapsulationMechanism : IDisposable
    {
        private class Native
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            [SuppressMessage("ReSharper", "InconsistentNaming")]
            public readonly struct OQS_KEM
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
                public readonly nuint PublicKeyLength;

                /// <summary>
                /// The (maximum) length, in bytes, of secret keys for this KEM.
                /// </summary>
                public readonly nuint SecretKeyLength;

                /// <summary>
                /// The (maximum) length, in bytes, of ciphertexts for this KEM.
                /// </summary>
                public readonly nuint CiphertextLength;

                /// <summary>
                /// The (maximum) length, in bytes, of shared secrets for this KEM.
                /// </summary>
                public readonly nuint SharedSecretLength;

                public readonly KeypairDelegate GenerateKeypair;

                public readonly EncapsulationDelegate Encapsulation;

                public readonly DecapsulationDelegate Decapsulation;

                /// <summary>
                /// Keypair generation algorithm.
                /// </summary>
                /// <param name="publicKey">The public key represented as a byte string.</param>
                /// <param name="secretKey">The secret key represented as a byte string.</param>
                /// <returns>Success or Error</returns>
                public delegate Status KeypairDelegate(ref byte publicKey, ref byte secretKey);

                /// <summary>
                /// Encapsulation algorithm.
                /// </summary>
                /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
                /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
                /// <param name="publicKey">The public key represented as a byte string.</param>
                /// <returns>Success or Error</returns>
                public delegate Status EncapsulationDelegate(ref byte ciphertext, ref byte sharedSecret, in byte publicKey);

                /// <summary>
                /// Decapsulation algorithm.
                /// </summary>
                /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
                /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
                /// <param name="secretKey">The secret key represented as a byte string.</param>
                /// <returns>Success or Error</returns>
                public delegate Status DecapsulationDelegate(ref byte sharedSecret, in byte ciphertext, in byte secretKey);
            }

            [DllImport("oqs")]
            public static extern IntPtr OQS_KEM_alg_identifier(nuint i);

            [DllImport("oqs")]
            public static extern int OQS_KEM_alg_count();

            [DllImport("oqs", CharSet = CharSet.Ansi)]
            public static extern int OQS_KEM_alg_is_enabled(string methodName);

            [DllImport("oqs", CharSet = CharSet.Ansi)]
            public static extern IntPtr OQS_KEM_new(string methodName);

            [DllImport("oqs")]
            public static extern void OQS_KEM_free(IntPtr kem);
        }

        private IntPtr _keyEncapsulationMechanismPtr;
        private readonly Native.OQS_KEM _keyEncapsulationMechanism;

        public static string[] SupportedMechanism { get; }

        public static string[] EnabledMechanism { get; }

        /// <summary>
        /// Printable string representing the name of the key encapsulation mechanism.
        /// </summary>
        public string MethodName => _keyEncapsulationMechanism.MethodName;

        /// <summary>
        /// Printable string representing the version of the cryptographic algorithm.
        /// </summary>
        public string Version => _keyEncapsulationMechanism.Version;

        /// <summary>
        /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
        /// </summary>
        public byte ClaimedNistLevel => _keyEncapsulationMechanism.ClaimedNistLevel;

        /// <summary>
        /// Whether the KEM offers IND-CCA security (TRUE) or IND-CPA security (FALSE).
        /// </summary>
        public bool IsIndCca => _keyEncapsulationMechanism.IsIndCca;

        /// <summary>
        /// The (maximum) length, in bytes, of public keys for this KEM.
        /// </summary>
        public nuint PublicKeyLength => _keyEncapsulationMechanism.PublicKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of secret keys for this KEM.
        /// </summary>
        public nuint SecretKeyLength => _keyEncapsulationMechanism.SecretKeyLength;

        /// <summary>
        /// The (maximum) length, in bytes, of ciphertexts for this KEM.
        /// </summary>
        public nuint CiphertextLength => _keyEncapsulationMechanism.CiphertextLength;

        /// <summary>
        /// The (maximum) length, in bytes, of shared secrets for this KEM.
        /// </summary>
        public nuint SharedSecretLength => _keyEncapsulationMechanism.SharedSecretLength;

        static KeyEncapsulationMechanism()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = Native.OQS_KEM_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(Native.OQS_KEM_alg_identifier((nuint) i));
                if (mechanismName == null) throw new OpenQuantumSafeException($"{nameof(mechanismName)} is null.");

                supportedMechanism.Add(mechanismName);

                if (Native.OQS_KEM_alg_is_enabled(mechanismName) == 1)
                {
                    enabledMechanism.Add(mechanismName);
                }
            }

            SupportedMechanism = supportedMechanism.ToArray();
            EnabledMechanism = enabledMechanism.ToArray();
        }

        public KeyEncapsulationMechanism(string keyEncapsulationMechanismAlgorithm)
        {
            if (!SupportedMechanism.Contains(keyEncapsulationMechanismAlgorithm)) throw new MechanismNotSupportedException(keyEncapsulationMechanismAlgorithm);
            if (!EnabledMechanism.Contains(keyEncapsulationMechanismAlgorithm)) throw new MechanismNotEnabledException(keyEncapsulationMechanismAlgorithm);

            _keyEncapsulationMechanismPtr = Native.OQS_KEM_new(keyEncapsulationMechanismAlgorithm);
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new OpenQuantumSafeException($"Not enough memory to create {keyEncapsulationMechanismAlgorithm} instance.");

            _keyEncapsulationMechanism = Marshal.PtrToStructure<Native.OQS_KEM>(_keyEncapsulationMechanismPtr);
        }

        ~KeyEncapsulationMechanism()
        {
            ReleaseUnmanagedResources();
        }

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            publicKey = new byte[PublicKeyLength];
            secretKey = new byte[SecretKeyLength];

            var result = _keyEncapsulationMechanism.GenerateKeypair(ref Unsafe.AsRef(publicKey[0]), ref Unsafe.AsRef(secretKey[0]));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void GenerateKeypair(Span<byte> publicKey, Span<byte> secretKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            var result = _keyEncapsulationMechanism.GenerateKeypair(ref MemoryMarshal.GetReference(publicKey), ref MemoryMarshal.GetReference(secretKey));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Encapsulation algorithm.
        /// </summary>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        public void Encapsulation(out byte[] ciphertext, out byte[] sharedSecret, ReadOnlySpan<byte> publicKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            ciphertext = new byte[CiphertextLength];
            sharedSecret = new byte[SharedSecretLength];

            var result = _keyEncapsulationMechanism.Encapsulation(ref Unsafe.AsRef(ciphertext[0]), ref Unsafe.AsRef(sharedSecret[0]), MemoryMarshal.GetReference(publicKey));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Encapsulation algorithm.
        /// </summary>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        public void Encapsulation(Span<byte> ciphertext, Span<byte> sharedSecret, ReadOnlySpan<byte> publicKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            var result = _keyEncapsulationMechanism.Encapsulation(ref MemoryMarshal.GetReference(ciphertext), ref MemoryMarshal.GetReference(sharedSecret), MemoryMarshal.GetReference(publicKey));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Decapsulation algorithm.
        /// </summary>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void Decapsulation(out byte[] sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> secretKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            sharedSecret = new byte[SharedSecretLength];

            var result = _keyEncapsulationMechanism.Decapsulation(ref Unsafe.AsRef(sharedSecret[0]), MemoryMarshal.GetReference(ciphertext), MemoryMarshal.GetReference(secretKey));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Decapsulation algorithm.
        /// </summary>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void Decapsulation(Span<byte> sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> secretKey)
        {
            if (_keyEncapsulationMechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(KeyEncapsulationMechanism));

            var result = _keyEncapsulationMechanism.Decapsulation(ref MemoryMarshal.GetReference(sharedSecret), MemoryMarshal.GetReference(ciphertext), MemoryMarshal.GetReference(secretKey));
            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        private void ReleaseUnmanagedResources()
        {
            Native.OQS_KEM_free(_keyEncapsulationMechanismPtr);
            _keyEncapsulationMechanismPtr = IntPtr.Zero;
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
    }
}