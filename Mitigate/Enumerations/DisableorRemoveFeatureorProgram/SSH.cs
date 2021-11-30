using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class SSH : Enumeration
    {
        public override string Name => "SSH Disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
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
            catch (SocketException e)
            {
                sshDisabled = true;
                
            }
            yield return new BooleanConfig("SSH disabled", sshDisabled);

        }
    }
}
