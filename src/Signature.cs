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
    public class Signature : IDisposable
    {
        private readonly IntPtr _signatureIntPtr;
        private readonly UnmanagedSignature _signature;

        public static string[] SupportedMechanism { get; }

        public static string[] EnabledMechanism { get; }

        /// <summary>
        /// Printable string representing the name of the signature scheme.
        /// </summary>
        public string MethodName
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.MethodName;
            }
        }

        /// <summary>
        /// Printable string representing the version of the cryptographic algorithm.
        /// </summary>
        public string Version
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.Version;
            }
        }

        /// <summary>
        /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
        /// </summary>
        public byte ClaimedNistLevel
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.ClaimedNistLevel;
            }
        }

        /// <summary>
        /// Whether the signature offers EUF-CMA security (TRUE) or not (FALSE).
        /// </summary>
        public bool IsEufCma
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.IsEufCma;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of public keys for this signature scheme.
        /// </summary>
        public UIntPtr PublicKeyLength
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.PublicKeyLength;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of secret keys for this signature scheme.
        /// </summary>
        public UIntPtr SecretKeyLength
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.SecretKeyLength;
            }
        }

        /// <summary>
        /// The (maximum) length, in bytes, of signatures for this signature scheme.
        /// </summary>
        public UIntPtr SignatureLength
        {
            get
            {
                if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));
                return _signature.SignatureLength;
            }
        }

        static Signature()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_SIG_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_SIG_alg_identifier(new UIntPtr((uint) i)));
                if (mechanismName == null) continue;

                supportedMechanism.Add(mechanismName);

                if (OQS_SIG_alg_is_enabled(mechanismName) == 1)
                {
                    enabledMechanism.Add(mechanismName);
                }
            }

            SupportedMechanism = supportedMechanism.ToArray();
            EnabledMechanism = enabledMechanism.ToArray();
        }

        public Signature(string signatureAlgorithm)
        {
            if (!SupportedMechanism.Contains(signatureAlgorithm)) throw new MechanismNotSupportedException(signatureAlgorithm);
            if (!EnabledMechanism.Contains(signatureAlgorithm)) throw new MechanismNotEnabledException(signatureAlgorithm);

            _signatureIntPtr = OQS_SIG_new(signatureAlgorithm);

            if (_signatureIntPtr == IntPtr.Zero) throw new OpenQuantumSafeException("Failed to initialize signature algorithm.");

            _signature = Marshal.PtrToStructure<UnmanagedSignature>(_signatureIntPtr);
        }

        ~Signature()
        {
            ReleaseUnmanagedResources();
        }

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr OQS_SIG_alg_identifier(UIntPtr i);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int OQS_SIG_alg_count();

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int OQS_SIG_alg_is_enabled(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr OQS_SIG_new(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void OQS_SIG_free(IntPtr sig);

        /// <summary>
        /// Keypair generation algorithm.
        /// </summary>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));

            publicKey = new byte[_signature.PublicKeyLength.ToUInt64()];
            secretKey = new byte[_signature.SecretKeyLength.ToUInt64()];

            var result = _signature.GenerateKeypair(publicKey, secretKey);

            if (result != Status.Success) throw new OpenQuantumSafeException(result);
        }

        /// <summary>
        /// Signature generation algorithm.
        /// </summary>
        /// <param name="signature">The signature on the message represented as a byte string.</param>
        /// <param name="message">The message to sign represented as a byte string.</param>
        /// <param name="secretKey">The secret key represented as a byte string.</param>
        public void Sign(out byte[] signature, byte[] message, byte[] secretKey)
        {
            if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));

            var resultSignature = new byte[_signature.SignatureLength.ToUInt64()];
            var signatureLength = new UIntPtr();

            var result = _signature.Sign(resultSignature, ref signatureLength, message, new UIntPtr((ulong) message.LongLength), secretKey);

            if (result != Status.Success) throw new OpenQuantumSafeException(result);

            signature = new byte[signatureLength.ToUInt64()];
            Buffer.BlockCopy(resultSignature, 0, signature, 0, (int) signatureLength.ToUInt32());
        }

        /// <summary>
        /// Signature verification algorithm.
        /// </summary>
        /// <param name="message">The message represented as a byte string.</param>
        /// <param name="signature">The signature on the message represented as a byte string.</param>
        /// <param name="publicKey">The public key represented as a byte string.</param>
        /// <returns>Success or Error</returns>
        public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
        {
            if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));

            var result = _signature.Verify(message, new UIntPtr((uint) message.Length), signature, new UIntPtr((uint) signature.Length), publicKey);

            return result switch
            {
                Status.Success => true,
                Status.Error => false,
                Status.ExternalLibErrorOpenSsl => false,
                var _ => throw new ArgumentOutOfRangeException()
            };
        }

        private void ReleaseUnmanagedResources()
        {
            if (_signatureIntPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(_signatureIntPtr));

            OQS_SIG_free(_signatureIntPtr);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
    }
}