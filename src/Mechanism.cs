using System;

namespace Tuckfirtle.OpenQuantumSafe
{
    public abstract class Mechanism : IDisposable
    {
        public string AlgorithmName { get; protected set; }

        public string AlgorithmVersion { get; protected set; }

        public byte ClaimedNistLevel { get; protected set; }

        public int PublicKeyLength { get; protected set; }

        public int SecretKeyLength { get; protected set; }

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