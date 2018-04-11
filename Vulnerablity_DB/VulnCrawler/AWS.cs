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
            public static string FilePath => @"D:\Account.xml";
            [XmlAttribute("EndPoint")]
            public string Endpoint { get; set; }
            [XmlAttribute("ID")]
            public string Id { get; set; }
            [XmlAttribute("PW")]
            public string Pw { get; set; }

        }
        
        private static Account account;

        static AWS() {
            // account = LoadAccount();
            account = new Account() {
                Endpoint = "aaa",
                Id = "bbb",
                Pw = "1231",

            };
            Console.WriteLine(account.Endpoint);
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
        
        public static void SaveAccount() {


            //File.SetAttributes(Account.FilePath, FileAttributes.Normal);

            // Serialization
            using (StreamWriter wr = new StreamWriter(Account.FilePath)) {
                XmlSerializer xs = new XmlSerializer(typeof(Account));
                xs.Serialize(wr, account);
            }

        }

    }

    
}
