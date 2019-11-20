namespace Tuckfirtle.OpenQuantumSafe.Exception
{
    public class OpenQuantumSafeException : System.Exception
    {
        public int Status { get; }

        public OpenQuantumSafeException() : base("Open quantum safe library has encounter an error.")
        {
        }

        public OpenQuantumSafeException(string message) : base(message)
        {
        }

        public OpenQuantumSafeException(int status) : base("Open quantum safe library has encounter an error.")
        {
            Status = status;
        }

        public OpenQuantumSafeException(int status, string message) : base(message)
        {
            Status = status;
        }
    }
}