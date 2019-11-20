namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public class MechanismNotEnabledException : MechanismException
    {
        public MechanismNotEnabledException(string requestMechanism) : base(requestMechanism, $"{requestMechanism} is not enabled.")
        {
        }
    }
}