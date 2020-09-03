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
        private struct OqsSig
        {
            public readonly IntPtr MethodName;

            public readonly IntPtr AlgVersion;

            public readonly byte ClaimedNistLevel;

            public readonly byte EufCma;

            public readonly UIntPtr LengthPublicKey;

            public readonly UIntPtr LengthSecretKey;

            public readonly UIntPtr LengthSignature;

            public readonly KeypairDelegate Keypair;

            public readonly SignDelegate Sign;

            public readonly VerifyDelegate Verify;

            public delegate IntPtr KeypairDelegate(byte[] publicKey, byte[] secretKey);

            public delegate IntPtr SignDelegate(byte[] signature, ref UIntPtr signatureLen, byte[] message, UIntPtr messageLen, byte[] secretKey);

            public delegate IntPtr VerifyDelegate(byte[] message, UIntPtr messageLen, byte[] signature, UIntPtr signatureLen, byte[] publicKey);
        }

        private readonly OqsSig _mechanism;

        public static string[] SupportedMechanism { get; }

        public static string[] EnabledMechanism { get; }

        public override string AlgorithmName { get; }

        public override string AlgorithmVersion { get; }

        public override byte ClaimedNistLevel => _mechanism.ClaimedNistLevel;

        public bool IsEufCma { get; }

        public override ulong PublicKeyLength { get; }

        public override ulong SecretKeyLength { get; }

        public ulong SignatureLength { get; }

        static Signature()
        {
            var supportedMechanism = new List<string>();
            var enabledMechanism = new List<string>();

            var mechanismCount = OQS_SIG_alg_count();

            for (var i = 0; i < mechanismCount; i++)
            {
                var mechanismName = Marshal.PtrToStringAnsi(OQS_SIG_alg_identifier((UIntPtr) i));
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

            MechanismPtr = OQS_SIG_new(signatureAlgorithm);

            if (MechanismPtr == IntPtr.Zero) throw new OpenQuantumSafeException("Failed to initialize signature algorithm.");

            var mechanism = Marshal.PtrToStructure<OqsSig>(MechanismPtr);
            _mechanism = mechanism;

            AlgorithmName = Marshal.PtrToStringAnsi(mechanism.MethodName);
            AlgorithmVersion = Marshal.PtrToStringAnsi(mechanism.AlgVersion);
            IsEufCma = mechanism.EufCma > 0;
            PublicKeyLength = mechanism.LengthPublicKey.ToUInt64();
            SecretKeyLength = mechanism.LengthSecretKey.ToUInt64();
            SignatureLength = mechanism.LengthSignature.ToUInt64();
        }

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_SIG_alg_identifier(UIntPtr i);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_SIG_alg_count();

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern int OQS_SIG_alg_is_enabled(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr OQS_SIG_new(string methodName);

        [DllImport("oqs", CallingConvention = CallingConvention.Cdecl)]
        private static extern void OQS_SIG_free(IntPtr sig);

        public override void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            publicKey = new byte[PublicKeyLength];
            secretKey = new byte[SecretKeyLength];

            var result = (Status) _mechanism.Keypair(publicKey, secretKey).ToInt64();

            if (result != Status.Success) throw new OpenQuantumSafeException((int) result);
        }

        public void Sign(out byte[] signature, in byte[] message, in byte[] secretKey)
        {
            Sign(out signature, message, Convert.ToUInt64(message.Length), secretKey);
        }

        public void Sign(out byte[] signature, in byte[] message, in ulong messageLength, in byte[] secretKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            var resultSignature = new byte[SignatureLength];
            var signatureLength = new UIntPtr(SignatureLength);
            var result = (Status) _mechanism.Sign(resultSignature, ref signatureLength, message, new UIntPtr(messageLength), secretKey).ToInt64();

            if (result != Status.Success) throw new OpenQuantumSafeException((int) result);

            signature = new byte[signatureLength.ToUInt64()];

            if (signatureLength.ToUInt64() > int.MaxValue)
            {
                Buffer.BlockCopy(resultSignature, 0, signature, 0, int.MaxValue);

                for (var i = Convert.ToUInt64(int.MaxValue); i < signatureLength.ToUInt64(); i++)
                {
                    signature[i] = resultSignature[i];
                }
            }
            else
            {
                Buffer.BlockCopy(resultSignature, 0, signature, 0, Convert.ToInt32(signatureLength.ToUInt64()));
            }
        }

        public bool Verify(in byte[] message, in byte[] signature, in byte[] publicKey)
        {
            return Verify(message, Convert.ToUInt64(message.Length), signature, Convert.ToUInt64(signature.Length), publicKey);
        }

        public bool Verify(in byte[] message, ulong messageLength, in byte[] signature, ulong signatureLength, in byte[] publicKey)
        {
            if (MechanismPtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(MechanismPtr));

            var result = (Status) _mechanism.Verify(message, new UIntPtr(messageLength), signature, new UIntPtr(signatureLength), publicKey).ToInt64();

            switch (result)
            {
                case Status.Success:
                    return true;

                case Status.Error:
                case Status.ExternalLibErrorOpenSsl:
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