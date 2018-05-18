using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {

           
        }
    }
}


namespace AWS_Center
{
    public static class VulnRDS
    {
        public static MySqlConnection Conn { get; set; }

        public class Vuln
        {
            public int VulnId { get; set; } /* 취약점 ID */
            public int LenBlock { get; set; } /* 취약점 BLOCK 길이 */
            public string RepositName { get; set; } /* 취약점 레파지토리 이름 */
            public string Cve { get; set; } /* 취약점 CVE */
            public string FuncName { get; set; } /* 취약점 함수 이름 */
            public string Language { get; set; } /* 취약점 언어 종류 */
            public string CodeOriBefore { get; set; } /* 취약점 패치 전 원본 코드 */
            public string CodeOriAfter { get; set; } /* 취약점 패치 후 원본 코드 */
            public string CodeAbsBefore { get; set; } /* 취약점 패치 전 추상화 코드 */
            public string CodeAbsAfter { get; set; } /* 취약점 패치 후 추상화 코드 */
            public string BlockHash { get; set; } /* 취약점 블록 해시 값 */
            // 생성자
            public Vuln()
            {


            }
        }

        public class User
        {
            public int UserId { get; set; } /* 유저 ID */
            public string RepositName { get; set; } /* 유저 레파지토리 이름 */
            public string Cve { get; set; } /* 취약점 CVE */
            public string CodeOriBefore { get; set; } /* 취약점 패치 전 원본 코드 */
            public string CodeOriAfter { get; set; } /* 취약점 패치 후 원본 코드 */
            public string FuncName { get; set; } /* 취약점 함수 이름 */
            public string DetectDate { get; set; } /* 검사 날짜 */
            // 생성자
            public User()
            {


            }

        }
        //connect
        public static void Connect()
        {
            MySqlConnectionStringBuilder builder = new MySqlConnectionStringBuilder()
            {
                Server = "vulndb.cby38wfppa7l.us-east-2.rds.amazonaws.com",
                UserID = "yhackerbv",
                Password = "guswhd12",
                Database = "vuln",
                Port = 3306,
            };
            string strConn = builder.ToString();
            builder = null;
            Conn = new MySqlConnection(strConn);
        }
        public static void InsertVulnData(Vuln vuln)
        {
            /*
             * DB에 취약점 데이터가 이미 있는지 검사해야함
             * 
             */

            Conn.Open();
            
        }

        //public static IEnumerable<string> SearchVulnData(int _len)
        //{
        //
        //}
    }
}
