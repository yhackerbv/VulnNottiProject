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
using System.Diagnostics;

namespace VulnCrawler
{
    class Program
    {
        static void Main(string[] args) {
            #region MySql 연결
            //SecureString s_key = GetConsoleSecurePassword();
            //Console.Clear();
            //string key = SecureStringToString(s_key)
            //AWS.SaveAccount();
            //AES aes = new AES();

            /* AWS 계정 정보 파일 읽음 */
            string txt = File.ReadAllText(@"Account.xml");
            // string xml = aes.AESDecrypt128(txt, key);
            string xml = txt;

            AWS.LoadAccount(xml);
            AWS.Account account = AWS.account;
           
            /* AWS 정보 출력 */
            Console.WriteLine($"Endpoint: {account.Endpoint}, ID: {account.Id}, PW: {account.Pw}");
            try
            {
                /* DB 접속 시도 */
                VulnRDS.Connect(account, "vuln");
            }
            catch(Exception e)
            {
                Console.WriteLine($"접속 에러 :: {e.ToString()}");
            }

            /* AWS 연결 여부 확인 */
            if (VulnRDS.Conn.State == System.Data.ConnectionState.Open)
            {
                Console.WriteLine("접속 성공");
                
            }
            else
            {
                Console.WriteLine("연결 실패");
                return;
            }
            #endregion

            Run();

        }

        /* 메인 동작 함수 */
        public static void Run() {  
            // Repository 폴더들이 있는 주소를 지정하면 하위 폴더 목록을 가져옴(Repository 목록)
            Regex.CacheSize = 50;

            /* C:\VulnC에 있는 Git Repository들로 돌아감 */
            var directorys = Directory.GetDirectories(@"c:\VulnC");
            if (directorys.Length == 0) {
                Console.WriteLine("Repository 목록 찾기 실패");
                return;
            }

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            // Repository 목록 만큼 반복함.
            foreach (var directory in directorys) {
                /* 폴더 중에 linux가 있으면 잠깐 넘어감 (너무 커서 테스트 힘듦) */
                if (directory.Contains("~"))
                {
                    continue;
                }
                // 템플릿 패턴화 T : VulnAbstractCrawler
                VulnWorker.Run<VulnC>(directory);
            }
            stopwatch.Stop();
            var hours = stopwatch.Elapsed.Hours;
            var minutes = stopwatch.Elapsed.Minutes;
            var seconds = stopwatch.Elapsed.Seconds;

            Console.WriteLine($"경과 시간 {hours.ToString("00")}:{minutes.ToString("00")}:{seconds.ToString("00")}");



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
