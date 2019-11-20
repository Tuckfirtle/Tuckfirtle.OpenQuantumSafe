namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public class MechanismNotSupportedException : MechanismException
    {
        public MechanismNotSupportedException(string requestMechanism) : base(requestMechanism, $"{requestMechanism} is not supported.")
        {
        }
    }
}