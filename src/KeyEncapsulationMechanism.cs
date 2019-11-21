﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class KeyEncapsulationMechanism : Mechanism
    {
        public static IReadOnlyList<string> SupportedMechanism { get; }

        public static IReadOnlyList<string> EnabledMechanism { get; }

        public bool IsIndCca => Mechanism.ind_cca;

        public int CipherTextLength => (int) Mechanism.length_ciphertext.ToUInt64();

        public int SharedSecretLength => (int) Mechanism.length_shared_secret.ToUInt64();

        private OQS_KEM Mechanism { get; }

        static KeyEncapsulationMechanism()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_KEM_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_KEM_alg_identifier(new UIntPtr((uint) i)));
                supportedMechanism.Add(mechanismName);

                if (OQS_KEM_alg_is_enabled(mechanismName) == 1)
                    enabledMechanism.Add(mechanismName);
            }

            SupportedMechanism = supportedMechanism;
            EnabledMechanism = enabledMechanism;
        }

        public KeyEncapsulationMechanism(string keyEncapsulationMechanismAlgorithm)
        {
            if (!SupportedMechanism.Contains(keyEncapsulationMechanismAlgorithm))
                throw new MechanismNotSupportedException(keyEncapsulationMechanismAlgorithm);

            if (!EnabledMechanism.Contains(keyEncapsulationMechanismAlgorithm))
                throw new MechanismNotEnabledException(keyEncapsulationMechanismAlgorithm);

            MechanismPtr = OQS_KEM_new(keyEncapsulationMechanismAlgorithm);

            if (MechanismPtr == IntPtr.Zero)
                throw new OpenQuantumSafeException("Failed to initialize key encapsulation mechanism algorithm.");

            Mechanism = Marshal.PtrToStructure<OQS_KEM>(MechanismPtr);

            AlgorithmName = Marshal.PtrToStringAnsi(Mechanism.method_name);
            AlgorithmVersion = Marshal.PtrToStringAnsi(Mechanism.alg_version);
            ClaimedNistLevel = Mechanism.claimed_nist_level;
            PublicKeyLength = (int) Mechanism.length_public_key.ToUInt64();
            SecretKeyLength = (int) Mechanism.length_secret_key.ToUInt64();
        }

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_KEM_alg_identifier(UIntPtr i);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_KEM_alg_count();

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_KEM_alg_is_enabled(string method_name);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_KEM_new(string method_name);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern void OQS_KEM_free(IntPtr sig);

        public override void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            publicKey = new byte[PublicKeyLength];
            secretKey = new byte[SecretKeyLength];

            var result = (Status) Mechanism.keypair(publicKey, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        public void Encapsulation(out byte[] cipherText, out byte[] sharedSecret, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            cipherText = new byte[CipherTextLength];
            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) Mechanism.encaps(cipherText, sharedSecret, publicKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        public void Decapsulation(out byte[] sharedSecret, in byte[] cipherText, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) Mechanism.decaps(sharedSecret, cipherText, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        protected override void Free(IntPtr mechanismPtr)
        {
            OQS_KEM_free(mechanismPtr);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct OQS_KEM
        {
            public readonly IntPtr method_name;

            public readonly IntPtr alg_version;

            public readonly byte claimed_nist_level;

            public readonly bool ind_cca;

            public readonly UIntPtr length_public_key;

            public readonly UIntPtr length_secret_key;

            public readonly UIntPtr length_ciphertext;

            public readonly UIntPtr length_shared_secret;

            public readonly keypair_delegate keypair;

            public readonly encaps_delegate encaps;

            public readonly decaps_delegate decaps;

            public delegate IntPtr keypair_delegate(byte[] public_key, byte[] secret_key);

            public delegate IntPtr encaps_delegate(byte[] ciphertext, byte[] shared_secret, byte[] public_key);

            public delegate IntPtr decaps_delegate(byte[] shared_secret, byte[] ciphertext, byte[] secret_key);
        }
    }
}