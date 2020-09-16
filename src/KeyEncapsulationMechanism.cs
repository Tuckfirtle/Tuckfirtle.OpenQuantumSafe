// Copyright (C) 2020, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;
using Tuckfirtle.OpenQuantumSafe.Unmanaged;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class KeyEncapsulationMechanism : IDisposable
    {
        private readonly IntPtr _keyEncapsulationMechanismIntPtr;
        private readonly UnmanagedKeyEncapsulationMechanism _keyEncapsulationMechanism;

        public static string[] SupportedMechanism { get; }

        public static string[] EnabledMechanism { get; }

        /// <summary>
        /// Printable string representing the name of the key encapsulation mechanism.
        /// </summary>
        public string MethodName
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.MethodName;
            }
        }

        /// <summary>
        /// Printable string representing the version of the cryptographic algorithm.
        /// </summary>
        public string Version
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.Version;
            }
        }

        /// <summary>
        /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
        /// </summary>
        public byte ClaimedNistLevel
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.ClaimedNistLevel;
            }
        }

        /// <summary>
        /// Whether the KEM offers IND-CCA security (TRUE) or IND-CPA security (FALSE).
        /// </summary>
        public bool IsIndCca
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.IsIndCca;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of public keys for this KEM.
        /// </summary>
        public UIntPtr PublicKeyLength
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.PublicKeyLength;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of secret keys for this KEM.
        /// </summary>
        public UIntPtr SecretKeyLength
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.SecretKeyLength;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of ciphertexts for this KEM.
        /// </summary>
        public UIntPtr CiphertextLength
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.CiphertextLength;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of shared secrets for this KEM.
        /// </summary>
        public UIntPtr SharedSecretLength
        {
            get
            {
                if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));
                return _keyEncapsulationMechanism.SharedSecretLength;
            }
        }

        static KeyEncapsulationMechanism()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_KEM_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_KEM_alg_identifier(new UIntPtr((uint) i)));
                if (mechanismName == null) continue;

                supportedMechanism.Add(mechanismName);

                if (OQS_KEM_alg_is_enabled(mechanismName) == 1)
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

            _keyEncapsulationMechanismIntPtr = OQS_KEM_new(keyEncapsulationMechanismAlgorithm);

            if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new OpenQuantumSafeException("Failed to initialize key encapsulation mechanism algorithm.");

            _keyEncapsulationMechanism = Marshal.PtrToStructure<UnmanagedKeyEncapsulationMechanism>(_keyEncapsulationMechanismIntPtr);
        }

        ~KeyEncapsulationMechanism()
        {
            ReleaseUnmanagedResources();
        }

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr OQS_KEM_alg_identifier(UIntPtr i);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int OQS_KEM_alg_count();

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int OQS_KEM_alg_is_enabled(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr OQS_KEM_new(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void OQS_KEM_free(IntPtr kem);

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));

            publicKey = new byte[_keyEncapsulationMechanism.PublicKeyLength.ToUInt64()];
            secretKey = new byte[_keyEncapsulationMechanism.SecretKeyLength.ToUInt64()];

            var result = _keyEncapsulationMechanism.GenerateKeypair(publicKey, secretKey);

            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Encapsulation algorithm.
        /// </summary>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        public void Encapsulation(out byte[] ciphertext, out byte[] sharedSecret, byte[] publicKey)
        {
            if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));

            ciphertext = new byte[_keyEncapsulationMechanism.CiphertextLength.ToUInt64()];
            sharedSecret = new byte[_keyEncapsulationMechanism.SharedSecretLength.ToUInt64()];

            var result = _keyEncapsulationMechanism.Encapsulation(ciphertext, sharedSecret, publicKey);

            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Decapsulation algorithm.
        /// </summary>
        /// <param name="sharedSecret">The shared secret represented as a byte string.</param>
        /// <param name="ciphertext">The ciphertext (encapsulation) represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void Decapsulation(out byte[] sharedSecret, byte[] ciphertext, byte[] secretKey)
        {
            if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));

            sharedSecret = new byte[_keyEncapsulationMechanism.SharedSecretLength.ToUInt64()];

            var result = _keyEncapsulationMechanism.Decapsulation(sharedSecret, ciphertext, secretKey);

            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        private void ReleaseUnmanagedResources()
        {
            if (_keyEncapsulationMechanismIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_keyEncapsulationMechanismIntPtr));

            OQS_KEM_free(_keyEncapsulationMechanismIntPtr);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
    }
}