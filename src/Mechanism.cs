using System;

namespace Tuckfirtle.OpenQuantumSafe
{
    public abstract class Mechanism : IDisposable
    {
        public abstract string AlgorithmName { get; }

        public abstract string AlgorithmVersion { get; }

        public abstract byte ClaimedNistLevel { get; }

        public abstract ulong PublicKeyLength { get; }

        public abstract ulong SecretKeyLength { get; }

        protected IntPtr MechanismPtr { get; set; }

        ~Mechanism()
        {
            ReleaseUnmanagedResources();
        }

        public abstract void GenerateKeypair(out byte[] publicKey, out byte[] secretKey);

        protected abstract void Free(IntPtr mechanismPtr);

        private void ReleaseUnmanagedResources()
        {
            if (MechanismPtr != IntPtr.Zero)
                Free(MechanismPtr);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
    }
}