using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

//using MySql.Data.MySqlClient;
using AESENC;
using System.Security;
using System.Runtime.InteropServices;

namespace VulnCrawler
{
    class Program
    {
        static void Main(string[] args) {
            #region MySql 연결
            //SecureString s_key = GetConsoleSecurePassword();
            //Console.Clear();
            //string key = SecureStringToString(s_key);
            ////AWS.SaveAccount();
            //AES aes = new AES();
            //string txt = File.ReadAllText(@"Account.xml");
            //string xml = aes.AESDecrypt128(txt, key);

            //AWS.LoadAccount(xml);

            //AWS.Account account = AWS.account;

            //Console.WriteLine($"Endpoint: {account.Endpoint}, ID: {account.Id}, PW: {account.Pw}");

            //MySqlConnectionStringBuilder builder = new MySqlConnectionStringBuilder {
            //    Server = "",
            //    UserID = id,
            //    Password = pw,
            //    Database = "vuln",
            //    Port = 3306
            //};

            //string strConn = builder.ToString();
            //builder = null;
            //MySqlConnection conn = new MySqlConnection(strConn);

            //try {

            //    String sql = "INSERT INTO members (id, pwd, name) " +
            //                    "VALUES ('gon', '111', '김삿갓')";

            //    MySqlCommand cmd = new MySqlCommand(sql, conn);

            //    conn.Open();

            //    cmd.ExecuteNonQuery();
            //    conn.Close();
            //} catch (Exception e) {
            //    Console.WriteLine(e.ToString());
            //}
            #endregion

            Run();

        }
        public static void Run() {
            // Repository 폴더들이 있는 주소를 지정하면 하위 폴더 목록을 가져옴(Repository 목록)

            // var fields = VulnWorker.GetCriticalVariant(@"return _is_safe_url(url, host) and _is_safe_url(url.replace('\\', '/'), host)");
            var c = new VulnC();
            var fields = c.ExtractCriticalVariant(@"!DoReadFile (infile, &ds64_chunk, sizeof (DS64Chunk), &bcount) ||/* aaaa */");
            foreach (var item in fields)
            {
                Console.WriteLine(item);
            }
            return;
            var directorys = Directory.GetDirectories(@"c:\VulnPy");
            if (directorys.Length == 0) {
                Console.WriteLine("Repository 목록 찾기 실패");
                return;
            }
            // Repository 목록 만큼 반복함.
            foreach (var directory in directorys) {
                // 템플릿 패턴화 T : VulnAbstractCrawler
                VulnWorker.Run<VulnPython>(directory);
            }
        }

        #region Secure string input
        static String SecureStringToString(SecureString value) {
            IntPtr valuePtr = IntPtr.Zero;
            try {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(valuePtr);
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

 
        private static SecureString GetConsoleSecurePassword() {
            SecureString pwd = new SecureString();
            while (true) {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter) {
                    break;
                } else if (i.Key == ConsoleKey.Backspace) {
                    pwd.RemoveAt(pwd.Length - 1);
                    Console.Write("\b \b");
                } else {
                    pwd.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }
            return pwd;
        }
#endregion


        /// <summary>
        /// 디렉토리 삭제 함수
        /// </summary>
        /// <param name="targetDir"></param>
        public static void DeleteDirectory(string targetDir) {
            File.SetAttributes(targetDir, FileAttributes.Normal);

            string[] files = Directory.GetFiles(targetDir);
            string[] dirs = Directory.GetDirectories(targetDir);

            foreach (string file in files) {
                File.SetAttributes(file, FileAttributes.Normal);
                File.Delete(file);
            }

            foreach (string dir in dirs) {
                DeleteDirectory(dir);
            }

            Directory.Delete(targetDir, false);
        }




    }
}
