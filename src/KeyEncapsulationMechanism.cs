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
        private struct OqsKem
        {
            public readonly IntPtr MethodName;

            public readonly IntPtr AlgVersion;

            public readonly byte ClaimedNistLevel;

            public readonly byte IndCca;

            public readonly UIntPtr LengthPublicKey;

            public readonly UIntPtr LengthSecretKey;

            public readonly UIntPtr LengthCiphertext;

            public readonly UIntPtr LengthSharedSecret;

            public readonly KeypairDelegate Keypair;

            public readonly EncapsDelegate Encaps;

            public readonly DecapsDelegate Decaps;

            public delegate IntPtr KeypairDelegate(byte[] publicKey, byte[] secretKey);

            public delegate IntPtr EncapsDelegate(byte[] ciphertext, byte[] sharedSecret, byte[] publicKey);

            public delegate IntPtr DecapsDelegate(byte[] sharedSecret, byte[] ciphertext, byte[] secretKey);
        }

        private readonly OqsKem _mechanism;

        public static string[] SupportedMechanism { get; }

        public static string[] EnabledMechanism { get; }

        public override string AlgorithmName { get; }

        public override string AlgorithmVersion { get; }

        public override byte ClaimedNistLevel => _mechanism.ClaimedNistLevel;

        public bool IsIndCca { get; }

        public override ulong PublicKeyLength { get; }

        public override ulong SecretKeyLength { get; }

        public ulong CipherTextLength { get; }

        public ulong SharedSecretLength { get; }

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

            MechanismPtr = OQS_KEM_new(keyEncapsulationMechanismAlgorithm);

            if (MechanismPtr == IntPtr.Zero) throw new OpenQuantumSafeException("Failed to initialize key encapsulation mechanism algorithm.");

            var mechanism = Marshal.PtrToStructure<OqsKem>(MechanismPtr);
            _mechanism = mechanism;

            AlgorithmName = Marshal.PtrToStringAnsi(mechanism.MethodName);
            AlgorithmVersion = Marshal.PtrToStringAnsi(mechanism.AlgVersion);
            IsIndCca = mechanism.IndCca > 0;
            PublicKeyLength = mechanism.LengthPublicKey.ToUInt64();
            SecretKeyLength = mechanism.LengthSecretKey.ToUInt64();
            CipherTextLength = mechanism.LengthCiphertext.ToUInt64();
            SharedSecretLength = mechanism.LengthSharedSecret.ToUInt64();
        }

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_KEM_alg_identifier(UIntPtr i);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_KEM_alg_count();

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_KEM_alg_is_enabled(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_KEM_new(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern void OQS_KEM_free(IntPtr sig);

        public override void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            publicKey = new byte[PublicKeyLength];
            secretKey = new byte[SecretKeyLength];

            var result = (Status) _mechanism.Keypair(publicKey, secretKey).ToInt64();

            if (result != Status.Success) throw new OpenQuantumSafeException((int) result);
        }

        public void Encapsulation(out byte[] cipherText, out byte[] sharedSecret, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            cipherText = new byte[CipherTextLength];
            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) _mechanism.Encaps(cipherText, sharedSecret, publicKey).ToInt64();

            if (result != Status.Success) throw new OpenQuantumSafeException((int) result);
        }

        public void Decapsulation(out byte[] sharedSecret, in byte[] cipherText, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            sharedSecret = new byte[SharedSecretLength];

            var result = (Status) _mechanism.Decaps(sharedSecret, cipherText, secretKey).ToInt64();

            if (result != Status.Success) throw new OpenQuantumSafeException((int) result);
        }

        protected override void Free(IntPtr mechanismPtr)
        {
            OQS_KEM_free(mechanismPtr);
        }
    }
}