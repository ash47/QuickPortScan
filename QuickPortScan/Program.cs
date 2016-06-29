using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace QuickPortScan
{
    class Program
    {
        static void Main(string[] args)
        {
            // Configuration files
            string hostsFile = "hosts.txt";
            string portsFile = "ports.txt";
            string outFile = "output.txt";

            // Max number of threads to use at once
            int maxThreads = 20;

            // Read in the hosts file, convert to array of IPs
            if (!System.IO.File.Exists(hostsFile))
            {
                Console.WriteLine("Please create hosts.txt");
                return;
            }
            string[] hostStringArray = System.IO.File.ReadAllLines(hostsFile);
            List<IPAddress> ipAddressList = new List<IPAddress>();
            for(int i=0; i<hostStringArray.Length; ++i)
            {
                IPAddress ip;
                string ipString = hostStringArray[i];
                try
                {
                    // Try to parse it as an IP Address
                    ip = IPAddress.Parse(ipString);
                }
                catch
                {
                    // Failed, try to do a DNS lookup of the hostname
                    try
                    {
                        IPHostEntry ipHostInfo = Dns.GetHostEntry(ipString);
                        ip = ipHostInfo.AddressList[0];
                    }
                    catch (Exception e)
                    {
                        // DNS lookup failed, move onto the next line
                        continue;
                    }
                }

                // Add the IP
                ipAddressList.Add(ip);
            }
            IPAddress[] allIPs = ipAddressList.ToArray();

            // Read in ports file, conert to array of ints
            if (!System.IO.File.Exists(portsFile))
            {
                Console.WriteLine("Please create ports.txt");
                return;
            }
            string[] portStringArray = System.IO.File.ReadAllLines(portsFile);
            List<int> portList = new List<int>();

            for(int i=0; i<portStringArray.Length; ++i)
            {
                // Attempt to parse as an int
                try
                {
                    int port = Int32.Parse(portStringArray[i]);
                    portList.Add(port);
                }
                catch
                {
                    // Do nothing
                }
            }
            int[] allPorts = portList.ToArray();

            // If old file exists, delete if
            if (System.IO.File.Exists(outFile))
            {
                try
                {
                    System.IO.File.Delete(outFile);
                }
                catch
                {
                    Console.WriteLine("Failed to delete old log file " + outFile);
                    return;
                }
            }

            // Is the scan currently active?
            bool scanActive = true;

            // Do the port scan
            PortScanner scanner = new PortScanner(allIPs, allPorts);
            scanner.setMaxThreads(maxThreads);
            scanner.scan(delegate(List<ScanResult> results)
            {
                // Log that the scan has finished
                Console.WriteLine("Port scan has finished!");

                // Log how many we found
                Console.WriteLine("Found " + results.Count + " open ip/port combos!");
                
                // Log each open port and ip
                foreach(ScanResult result in results)
                {
                    string resultText = result.ip + "\t" + result.port;
                    Console.WriteLine(resultText);
                    System.IO.File.AppendAllText(outFile, resultText + Environment.NewLine);
                }

                // Scan is done
                scanActive = false;
            });

            // Do not exit 
            while(scanActive)
            {
                // Sleep
                System.Threading.Thread.Sleep(100);
            }
        }
    }
}
