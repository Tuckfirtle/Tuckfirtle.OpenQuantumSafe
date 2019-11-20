namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public abstract class MechanismException : System.Exception
    {
        public string RequestedMechanism { get; }

        protected MechanismException(string requestedMechanism)
        {
            RequestedMechanism = requestedMechanism;
        }

        protected MechanismException(string requestedMechanism, string message) : base(message)
        {
            RequestedMechanism = requestedMechanism;
        }
    }
}