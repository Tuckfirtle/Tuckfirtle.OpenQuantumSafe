using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe
{
    public class Signature : Mechanism
    {
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

            public delegate IntPtr sign_delegate(byte[] signature, ref UIntPtr signature_len, byte[] message, UIntPtr message_len, byte[] secret_key);

            public delegate IntPtr verify_delegate(byte[] message, UIntPtr message_len, byte[] signature, UIntPtr signature_len, byte[] public_key);
        }

        public static IReadOnlyList<string> SupportedMechanism { get; }

        public static IReadOnlyList<string> EnabledMechanism { get; }

        public override string AlgorithmName { get; }

        public override string AlgorithmVersion { get; }

        public override byte ClaimedNistLevel => Mechanism.claimed_nist_level;

        public bool IsEufCma => Mechanism.euf_cma;

        public override ulong PublicKeyLength => Mechanism.length_public_key.ToUInt64();

        public override ulong SecretKeyLength => Mechanism.length_secret_key.ToUInt64();

        public ulong SignatureLength => Mechanism.length_signature.ToUInt64();

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

        public void Sign(out byte[] signature, in byte[] message, in byte[] secretKey)
        {
            Sign(out signature, message, Convert.ToUInt64(message.Length), secretKey);
        }

        public void Sign(out byte[] signature, in byte[] message, in ulong messageLength, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            var resultSignature = new byte[SignatureLength];
            var signatureLength = new UIntPtr(SignatureLength);
            var result = (Status) Mechanism.sign(resultSignature, ref signatureLength, message, new UIntPtr(messageLength), secretKey).ToInt64();

            if (result != Status.Success)
                throw new OpenQuantumSafeException((int) result);

            signature = new byte[signatureLength.ToUInt64()];

            if (signatureLength.ToUInt64() > int.MaxValue)
            {
                Buffer.BlockCopy(resultSignature, 0, signature, 0, int.MaxValue);

                for (var i = Convert.ToUInt64(int.MaxValue); i < signatureLength.ToUInt64(); i++)
                    signature[i] = resultSignature[i];
            }
            else
                Buffer.BlockCopy(resultSignature, 0, signature, 0, Convert.ToInt32(signatureLength.ToUInt64()));
        }

        public bool Verify(in byte[] message, in byte[] signature, in byte[] publicKey)
        {
            return Verify(message, Convert.ToUInt64(message.Length), signature, Convert.ToUInt64(signature.Length), publicKey);
        }

        public bool Verify(in byte[] message, ulong messageLength, in byte[] signature, ulong signatureLength, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(MechanismPtr));

            var result = (Status) Mechanism.verify(message, new UIntPtr(messageLength), signature, new UIntPtr(signatureLength), publicKey).ToInt64();

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
    }
}