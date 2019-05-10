using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using WinSCP;

namespace xFTPClient
{
    class Program
    {
        private const string KnownHosts = "KnownHosts.json";
        private static string UserInput => Console.ReadLine();
        private static SessionOptions SavedSessionOptions { get; set; }
        private static string UserCommand { get; set; }
        private static string Fingerprint { get; set; }

        static void Main(string[] args)
        {
            if (!File.Exists(KnownHosts))
            {
                var hostData = new JObject
                {
                    { "KnownHosts", new JArray{} }
                };

                File.AppendAllText(KnownHosts, hostData.ToString());
            }

            while (UserInput != "exit")
            {
                switch (UserInput)
                {
                    case "connect":
                        Console.WriteLine("Connection format: address;port;username;password;path/to/cert");
                        SetSession(UserInput);
                        Connect(SavedSessionOptions, "SHA-256");
                        break;
                }
            }
        }


        // Configure the session options
        private static SessionOptions SetSession(string options)
        {
            var connectionBuilder = options.Split(";");
            var sessionOptions = new SessionOptions
            {
                Protocol = Protocol.Sftp,
                HostName = connectionBuilder[0],
                PortNumber = int.Parse(connectionBuilder[1]),
                UserName = connectionBuilder[2],
                SshPrivateKeyPath = connectionBuilder[3]
            };
            return SavedSessionOptions = sessionOptions;
        }

        // Connect to the target host
        private static void Connect(SessionOptions sessionOptions, string algorithm)
        {
            var currentOptions = sessionOptions;
            var checkForValue = HostIsKnown(KnownHosts, currentOptions.HostName, currentOptions.PortNumber);
            if (checkForValue == null)
            {
                // We connect once to retrieve the fingerprint from the server
                // This should only be done on a uncomprimised network
                using (var session = new Session())
                {
                    Fingerprint = session.ScanFingerprint(new SessionOptions
                    {
                        Protocol = Protocol.Sftp,
                        HostName = currentOptions.HostName,
                        PortNumber = currentOptions.PortNumber,
                        UserName = currentOptions.UserName,
                        SshPrivateKeyPath = currentOptions.SshPrivateKeyPath,
                        GiveUpSecurityAndAcceptAnySshHostKey = true
                    },  algorithm);

                    var updateValues = JObject.Parse(File.ReadAllText(KnownHosts));
                    var value = (JArray)updateValues["KnownHosts"];

                    value.Add($"{currentOptions.HostName}:{currentOptions.PortNumber}:{Fingerprint}");

                    File.WriteAllText(KnownHosts, updateValues.ToString());

                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unabled to find cached fingerprint, retrieving new!");
                    Console.ResetColor();
                }
            }

            if (checkForValue != null)
            {
                currentOptions.SshHostKeyFingerprint = checkForValue;
                Console.WriteLine("Found fingerprint value: " + checkForValue);
            }
        }

        // Check for cached fingerprint
        private static string HostIsKnown(string file, string hostname, int port)
        {
            var parseFile = JObject.Parse(File.ReadAllText(file));
            var readArray = (JArray)parseFile["KnownHosts"];
            var convertArray = readArray.Select(jv => (string)jv).ToList();
            if (convertArray.Where(x => x.Contains($"{hostname}:{port}")).FirstOrDefault() != null)
            {
                // This method can probably be improved, but it works... :^)
                var printFinger = convertArray.Select(s => s).Where(x => x.Contains($"{hostname}:{port}")).ToArray();
                var retrieveValue = printFinger[0].Split(":").ToArray();
                return retrieveValue[2];
            }
            return null;
        }
    }
}