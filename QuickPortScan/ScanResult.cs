using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace QuickPortScan
{
    public class ScanResult
    {
        // The IP Address of this result
        private IPAddress _ip;
        public IPAddress ip
        {
            get
            {
                return _ip;
            }
        }

        // The port of this result
        private int _port;
        public int port
        {
            get
            {
                return _port;
            }
        }

        public ScanResult(IPAddress theIP, int thePort)
        {
            // Store it
            _ip = theIP;
            _port = thePort;
        }
    }
}
