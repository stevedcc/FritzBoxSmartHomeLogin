﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml;

namespace SessionID
{
    public record FritzBoxAddress
    {
        private readonly string _scheme;
        private readonly string _host;
        public virtual string Url => $"{_scheme}://{_host}";

        public FritzBoxAddress(string scheme, string host)
        {
            _scheme = scheme;
            _host = host;
        }
    }

    public record FritzBoxHomeAutomationCommand : FritzBoxAddress
    {
        private readonly string _commandName;
        private readonly string _ain;
        private readonly string _sid;
        
        public override string Url => $"{base.Url}/webservices/homeautoswitch.lua?{_ain}{_commandName}{_sid}";

        public FritzBoxHomeAutomationCommand(FritzBoxAddress fritzBoxAddress, string sid, string commandName, string ain = "")
            : base(fritzBoxAddress)
        {
            _sid = $"sid={sid}";
            _commandName = $"switchcmd={commandName}&";
            _ain = string.IsNullOrEmpty(ain) ? string.Empty : $"ain={ain}&";
        }
    }

    public class FritzBoxLogin
    {
        private readonly HttpClient _httpClient;
        private readonly FritzBoxAddress _fritzBoxAddress;
        private readonly string _path;
        
        private string _sid;
        private string _userName;
        private string _response;

        private string UserName
        {
            get => _userName;
            set => _userName = (string.IsNullOrWhiteSpace(value) ? string.Empty : $"?username={value}");
        }

        private string Password { get;  }

        private string Sid
        {
            get => _sid;
            set
            {
                var prefix = string.IsNullOrWhiteSpace(UserName) ? "?" : "&";
                
                _sid = (string.IsNullOrWhiteSpace(value) ? string.Empty : $"{prefix}sid={value}");
            }
        }

        private string Response
        {
            get => _response;
            set
            {
                var prefix = string.IsNullOrWhiteSpace(UserName) && string.IsNullOrWhiteSpace(Sid)? "?" : "&";
                
                _response = (string.IsNullOrWhiteSpace(value) ? string.Empty : $"{prefix}response={value}");
            }
        }

        private string Url => $"{_fritzBoxAddress.Url}/{_path}{UserName}{Sid}{Response}";

        public FritzBoxLogin(HttpClient httpClient, FritzBoxAddress fritzBoxAddress, string path, string userName, string password)
        {
            _httpClient = httpClient;
            _fritzBoxAddress = fritzBoxAddress;
           
           _path = path;
           UserName = userName;
           Password = password;
       }
        
        public async Task<string> GetSessionIdAsync()
        {
            Console.WriteLine($"Url: {Url}");

            var sid = await LoginAsync();
            Console.WriteLine($"SID: {sid}");
            Sid = sid;
            var page = await ReadPageAsync();
            Console.WriteLine($"Page content: {Environment.NewLine}{Utils.PrettyPrint(page)}");
            
            return sid;
        }

        private async Task<string> ReadPageAsync()
        {
            return await Utils.ReadXmlFromUrl(_httpClient, Url);
        }
        
        // based on c# example in https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/Session-ID_deutsch_13Nov18.pdf
        private async Task<string> LoginAsync()
        {
            var unauthenticatedXml = await Utils.ReadXmlFromUrl(_httpClient, Url);
                
            var unauthenticatedDoc = XDocument.Parse(unauthenticatedXml);

            // Brute-Force-Protection.
            string szBlocktime = Utils.GetFirstMatchingElementValue(unauthenticatedDoc, "BlockTime");
            int blockTime = Int32.Parse(szBlocktime);
            if (blockTime > 0)
            {
                Console.WriteLine($"waiting {blockTime.ToString()}sec. ...");
                await Task.Delay(blockTime * 1000);
            }
            string sid = Utils.GetFirstMatchingElementValue(unauthenticatedDoc, "SID");
            if (sid == "0000000000000000")
            {
                string responseUser = Utils.GetFirstMatchingElementValue(unauthenticatedDoc, "User");
                if (string.IsNullOrEmpty(UserName))
                {
                    UserName = responseUser;
                }

                string challenge = Utils.GetFirstMatchingElementValue(unauthenticatedDoc, "Challenge");
                
                Response = GetResponse(challenge, Password);

                var authenticatedXml = await Utils.ReadXmlFromUrl(_httpClient, Url);

                var authenticatedDoc = XDocument.Parse(authenticatedXml);
                
                sid = Utils.GetFirstMatchingElementValue(authenticatedDoc, "SID");
            }
            return sid;
        }
        
        // from c# example in https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/Session-ID_deutsch_13Nov18.pdf
        private string GetResponse(string challenge, string password)
        {
            return $"{challenge}-{GetMD5Hash(challenge + "-" + password)}";
        }
        
        // based on c# example in https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/Session-ID_deutsch_13Nov18.pdf
        private string GetMD5Hash(string input)
        {
            var md5Hasher = MD5.Create();
            
            // UTF-8 > UTF-16LE
            var data = md5Hasher.ComputeHash(Encoding.Unicode.GetBytes(input));
            var sb = new StringBuilder();

            foreach (var b in data) 
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }

    public static class Utils
    {
        public static async Task<string> ReadXmlFromUrl(HttpClient httpClient, string url)
        {
            var pageResponse = await httpClient.GetAsync(url);

            using var loginReader = new StreamReader(await pageResponse.Content.ReadAsStreamAsync());

            return await loginReader.ReadToEndAsync();
        }
        
        public static string GetFirstMatchingElementValue(XDocument doc, string name)
        {
            var info = doc.FirstNode as XElement;
            
            return info?.Descendants(name).FirstOrDefault()?.Value ?? string.Empty;
        }
        
        // from https://stackoverflow.com/questions/1123718/format-xml-string-to-print-friendly-xml-string
        public static string PrettyPrint(string xml)
        {
            using var stringWriter = new StringWriter();
            using var writer = new XmlTextWriter(stringWriter);
            var doc = new XmlDocument();

            try
            {
                // Load the XmlDocument with the XML.
                doc.LoadXml(xml);

                writer.Formatting = Formatting.Indented;

                // Write the XML into a formatting XmlTextWriter
                doc.WriteContentTo(writer);
                writer.Flush();

                return stringWriter.GetStringBuilder().ToString();
                
            }
            catch (XmlException)
            {
                return "Error Decoding XML";
            }
        }
        
        public static string GetStringFromConsole(bool hideInput)
        {
            var userKeys = new List<char>();
            
            do
            {
                var key = Console.ReadKey(hideInput);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace && userKeys.Count > 0)
                {
                    userKeys.RemoveAt(userKeys.Count - 1);
                    if (hideInput)
                    {
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    userKeys.Add(key.KeyChar);
                    if (hideInput)
                    {
                        Console.Write("*");
                    }
                }
            } while (true);

            return new string(userKeys.ToArray());
        }
    }

    public static class Program
    {
        private static readonly HttpClient HttpClient = new HttpClient();

        static async Task Main()
        {
            var fritzBoxAddress = new FritzBoxAddress("http", "fritz.box");

            Console.WriteLine("Enter User name for the FritzBox.  Leave empty to use the first user from the login xml.");
            var username = Utils.GetStringFromConsole(false);
            
            Console.WriteLine("Enter password");
            var password = Utils.GetStringFromConsole(true);

            var loginData = new FritzBoxLogin(HttpClient, fritzBoxAddress, "login_sid.lua", username, password);
            var sid = await loginData.GetSessionIdAsync();

            var commandData = new FritzBoxHomeAutomationCommand(fritzBoxAddress, sid, "getdevicelistinfos");
            await ReadDevices(HttpClient, commandData.Url);
        }

        private static async Task ReadDevices(HttpClient httpClient, string url)
        {
            var xml = await Utils.ReadXmlFromUrl(httpClient, url);

            Console.WriteLine($"device content: {Environment.NewLine}{Utils.PrettyPrint(xml)}");
        }
    }
}