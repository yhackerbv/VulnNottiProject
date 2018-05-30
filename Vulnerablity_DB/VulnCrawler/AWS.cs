using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace VulnCrawler
{
    public static class AWS
    {
        [XmlRoot("MySqlAccountInfo")]
        public class Account
        {
            public static string FilePath => @"Account.xml";
            [XmlAttribute("EndPoint")]
            public string Endpoint { get; set; } = "127.0.0.1";
            [XmlAttribute("ID")]
            public string Id { get; set; } = "root";
            [XmlAttribute("PW")]
            public string Pw { get; set; } = "123";
        }
        public static Account account { get; private set; }
        static AWS() {
            // account = LoadAccount();
            account = new Account();
        }
        private static Account LoadAccount() {
            if (!File.Exists(Account.FilePath)) {
                return null;
            }
            Account acc = null;
            // Deserialization
            using (var reader = new StreamReader(Account.FilePath)) {
                XmlSerializer xs = new XmlSerializer(typeof(Account));
                acc = (Account)xs.Deserialize(reader);
            }
            return acc;
        }

        public static void LoadAccount(string txt) {
            Account acc = null;
            // Deserialization
            using (TextReader reader = new StringReader(txt)) {
                XmlSerializer xs = new XmlSerializer(typeof(Account));
                acc = (Account)xs.Deserialize(reader);
            }

            account = acc;

   
     
        }
        public static void SaveAccount() {
            // Serialization
            using (StreamWriter wr = new StreamWriter(Account.FilePath)) {
                XmlSerializer xs = new XmlSerializer(typeof(Account));
                xs.Serialize(wr, account);
            }

        }

        

    }

    
}
