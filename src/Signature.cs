using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class Signature : Mechanism
    {
        public static IReadOnlyList<string> SupportedMechanism { get; }

        public static IReadOnlyList<string> EnabledMechanism { get; }

        public string AlgorithmName { get; }

        public string AlgorithmVersion { get; }

        public byte ClaimedNistLevel => Mechanism.claimed_nist_level;

        public bool IsEufCma => Mechanism.euf_cma;

        public int PublicKeyLength => (int) Mechanism.length_public_key.ToUInt64();

        public int SecretKeyLength => (int) Mechanism.length_secret_key.ToUInt64();

        public int SignatureLength => (int) Mechanism.length_signature.ToUInt64();

        private OQS_SIG Mechanism { get; }

        static Signature()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_SIG_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_SIG_alg_identifier(new UIntPtr((uint) i)));
                supportedMechanism.Add(mechanismName);

                if (OQS_SIG_alg_is_enabled(mechanismName) == 1)
                    enabledMechanism.Add(mechanismName);
            }

            SupportedMechanism = supportedMechanism;
            EnabledMechanism = enabledMechanism;
        }

        public Signature(string signatureAlgorithm)
        {
            if (!SupportedMechanism.Contains(signatureAlgorithm))
                throw new MechanismNotSupportedException(signatureAlgorithm);

            if (!EnabledMechanism.Contains(signatureAlgorithm))
                throw new MechanismNotEnabledException(signatureAlgorithm);

            MechanismPtr = OQS_SIG_new(signatureAlgorithm);

            if (MechanismPtr == IntPtr.Zero)
                throw new OpenQuantumSafeException("Failed to initialize signature algorithm.");

            Mechanism = Marshal.PtrToStructure<OQS_SIG>(MechanismPtr);

            AlgorithmName = Marshal.PtrToStringAnsi(Mechanism.method_name);
            AlgorithmVersion = Marshal.PtrToStringAnsi(Mechanism.alg_version);
        }

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_SIG_alg_identifier(UIntPtr i);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_SIG_alg_count();

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_SIG_alg_is_enabled(string method_name);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_SIG_new(string method_name);

        [DllImport("liboqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern void OQS_SIG_free(IntPtr sig);

        public void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            publicKey = new byte[PublicKeyLength];
            secretKey = new byte[SecretKeyLength];

            var result = (Status) Mechanism.keypair(publicKey, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);
        }

        public void Sign(out byte[] signature, in byte[] message, in byte[] secretKey)
        {
            Sign(out signature, message, message.Length, secretKey);
        }

        public void Sign(out byte[] signature, in byte[] message, in int messageLength, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            signature = new byte[SignatureLength];
            var signatureLength = SignatureLength;
            var result = (Status) Mechanism.sign(signature, ref signatureLength, message, messageLength, secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);

            Array.Resize(ref signature, signatureLength);
        }

        public bool Verify(in byte[] message, in byte[] signature, in byte[] publicKey)
        {
            return Verify(message, message.Length, signature, signature.Length, publicKey);
        }

        public bool Verify(in byte[] message, int messageLength, in byte[] signature, int signatureLength, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            var result = (Status) Mechanism.verify(message, messageLength, signature, signatureLength, publicKey).ToInt64();

            switch (result)
            {
                case Status.Success:
                    return true;

                case Status.Error:
                    return false;

                default:
                    throw new OpenQuantumSafeException((int) result);
            }
        }

        protected override void Free(IntPtr mechanismPtr)
        {
            OQS_SIG_free(mechanismPtr);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct OQS_SIG
        {
            public readonly IntPtr method_name;

            public readonly IntPtr alg_version;

            public readonly byte claimed_nist_level;

            public readonly bool euf_cma;

            public readonly UIntPtr length_public_key;

            public readonly UIntPtr length_secret_key;

            public readonly UIntPtr length_signature;

            public readonly keypair_delegate keypair;

            public readonly sign_delegate sign;

            public readonly verify_delegate verify;

            public delegate IntPtr keypair_delegate(byte[] public_key, byte[] secret_key);

            public delegate IntPtr sign_delegate(byte[] signature, ref int signature_len, byte[] message, int message_len, byte[] secret_key);

            public delegate IntPtr verify_delegate(byte[] message, int message_len, byte[] signature, int signature_len, byte[] public_key);
        }
    }
}