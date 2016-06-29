using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace QuickPortScan
{
    public class PortScanner
    {
        // The array of IPs to scan
        private IPAddress[] allIPs;

        // The array of ports to scan
        private int[] allPorts;

        // Is a scan currently active?
        private bool scanActive = false;

        // The max number of threads
        private int maxThreads = 1;

        // Tracker for the current host that is being scanned
        private int ipUpto = 0;

        // Tracker for the current port that is being scanned
        private int portUpto = 0;

        // A lock used to ensure we don't scan the same thing twice
        Semaphore threadLock;

        // A lock used for accessing the result storage
        Semaphore resultLock;

        // The number of active threads
        private int activeThreads;

        // The list of open ports for hosts
        List<ScanResult> scanResults;

        // Return callback delegate
        public delegate void scanCallback(List<ScanResult> results);

        // Stores the callback
        scanCallback theCallback;

        // Init
        public PortScanner(IPAddress[] allIPsIn, int[] allPortsIn)
        {
            // Store the IPs and Ports
            allIPs = allIPsIn;
            allPorts = allPortsIn;

            // Init resources
            threadLock = new Semaphore(1, 1);
            resultLock = new Semaphore(1, 1);
        }

        // Sets the max number of threads to use
        public void setMaxThreads(int newMaxThreads)
        {
            // Max threads can only be changed if a scan isn't active
            if (scanActive) return;

            // Sets the max number of threads
            maxThreads = newMaxThreads;
        }

        // Perform a scan
        public void scan(scanCallback callback)
        {
            // Only one scan can happen at a time
            if (scanActive) return;
            scanActive = true;

            // Go to the start of the scan
            scanResults = new List<ScanResult>();
            ipUpto = 0;
            portUpto = 0;

            // Store callback
            theCallback = callback;

            // Log what we are about to do
            logActivity("Scanning " + allPorts.Length + " port per host on " + allIPs.Length + " hosts (" + (allPorts.Length * allIPs.Length) + " checks) using " + maxThreads + " threads...");

            // Spin up maxThreads number of threads
            activeThreads = maxThreads;
            for (int i=0; i<maxThreads; ++i)
            {
                // Spin up a thread
                ThreadPool.QueueUserWorkItem(portScanThread);
            }
        }

        // A port scan thread
        private void portScanThread(Object state)
        {
            // Infinite processing loop
            while(true)
            {
                // Grab a lock
                threadLock.WaitOne();

                // Anything left to scan?
                if (ipUpto >= allIPs.Length)
                {
                    // Unlock and exit
                    threadLock.Release();

                    // Lower the number of active threads
                    // Is this the last thread to close?
                    if (--activeThreads == 0)
                    {
                        // Run the callback
                        theCallback(scanResults);
                    }

                    // No scanning left, kill thread
                    return;
                }

                // Grab my ones
                IPAddress myIP = allIPs[ipUpto];
                int myPort = allPorts[portUpto];

                // Move onto the next port
                if (++portUpto >= allPorts.Length)
                {
                    // Port resets to 0
                    portUpto = 0;

                    // Increase the current ip we are looking at
                    ++ipUpto;
                }

                // Release the lock
                threadLock.Release();

                // Try to connect to the ip and port
                try
                {
                    // Connect, exception thrown if failure
                    Socket socket = new Socket(myIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    IPEndPoint endPoint = new IPEndPoint(myIP, myPort);
                    socket.Connect(endPoint);

                    // Connection successful! Log result
                    resultLock.WaitOne();

                    // Store results
                    scanResults.Add(new ScanResult(myIP, myPort));

                    // Log that we found an open port
                    logActivity("Discovered open port " + myPort + "/tcp on " + myIP);

                    // Release the lock
                    resultLock.Release();

                    // Disconnect
                    socket.Close();
                }
                catch
                {
                    // Failed to connect
                }
            }

            // Code should NEVER reach here
        }

        // Logs verbose activity to the console
        private void logActivity(string message)
        {
            Console.WriteLine(message);
        }
    }
}
