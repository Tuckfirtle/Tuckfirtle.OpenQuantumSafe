using System;

namespace Tuckfirtle.OpenQuantumSafe
{
    public abstract class Mechanism : IDisposable
    {
        protected IntPtr MechanismPtr { get; set; }

        protected abstract void Free(IntPtr mechanismPtr);

        private void ReleaseUnmanagedResources()
        {
            Free(MechanismPtr);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        ~Mechanism()
        {
            ReleaseUnmanagedResources();
        }
    }
}