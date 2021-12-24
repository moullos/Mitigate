using System;
using System.Collections.Generic;
using System.Net.Sockets;

namespace Mitigate.Enumerations
{
    class SSH : Enumeration
    {
        public override string Name => "SSH Disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Disable the SSH service if it is unnecessary.";
        public override string EnumerationDescription => "Checks if SSH is disabled";


        public override string[] Techniques => new string[] {
            "T1563"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            bool sshDisabled = false;
            try
            {
                Int32 port = 22;
                TcpClient client = new TcpClient("127.0.0.1", port);
            }
            catch (SocketException)
            {
                sshDisabled = true;
                
            }
            yield return new BooleanConfig("SSH disabled", sshDisabled);

        }
    }
}
