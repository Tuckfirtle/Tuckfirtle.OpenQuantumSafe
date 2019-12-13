using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class KeyEncapsulationMechanism : Mechanism
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct OQS_KEM
        {
            public readonly IntPtr method_name;

            public readonly IntPtr alg_version;

            public readonly byte claimed_nist_level;

            public readonly byte ind_cca;

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

        public static IReadOnlyList<string> SupportedMechanism { get; }

        public static IReadOnlyList<string> EnabledMechanism { get; }

        public override string AlgorithmName { get; }

        public override string AlgorithmVersion { get; }

        public override byte ClaimedNistLevel => _mechanism.claimed_nist_level;

        public bool IsIndCca => _mechanism.ind_cca > 0;

        public override ulong PublicKeyLength => _mechanism.length_public_key.ToUInt64();

        public override ulong SecretKeyLength => _mechanism.length_secret_key.ToUInt64();

        public ulong CipherTextLength => _mechanism.length_ciphertext.ToUInt64();

        public ulong SharedSecretLength => _mechanism.length_shared_secret.ToUInt64();

        private readonly OQS_KEM _mechanism;

        static KeyEncapsulationMechanism()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_KEM_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_KEM_alg_identifier(new UIntPtr(Convert.ToUInt32(i))));
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

            _mechanism = Marshal.PtrToStructure<OQS_KEM>(MechanismPtr);

            AlgorithmName = Marshal.PtrToStringAnsi(_mechanism.method_name);
            AlgorithmVersion = Marshal.PtrToStringAnsi(_mechanism.alg_version);
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

            var result = (Status) _mechanism.keypair(publicKey, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        public void Encapsulation(out byte[] cipherText, out byte[] sharedSecret, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            cipherText = new byte[CipherTextLength];
            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) _mechanism.encaps(cipherText, sharedSecret, publicKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        public void Decapsulation(out byte[] sharedSecret, in byte[] cipherText, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) _mechanism.decaps(sharedSecret, cipherText, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        protected override void Free(IntPtr mechanismPtr)
        {
            OQS_KEM_free(mechanismPtr);
        }
    }
}