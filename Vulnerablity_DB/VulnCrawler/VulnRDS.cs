using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;

namespace VulnCrawler
{
    public static class VulnRDS
    {
        public static AWS.Account Account { get; set; }
        public static string DbName { get; set; }
        public static MySqlConnection Conn { get; set; }
        public class Vuln
        {
            public int VulnId { get; set; } = -1; /* 취약점 ID */
            public int LenBlock { get; set; } = -1; /* 취약점 BLOCK 길이 */
            public string RepositName { get; set; } = "NULL"; /* 취약점 레파지토리 이름 */
            public string Cve { get; set; } = "NULL"; /* 취약점 CVE */
            public string FuncName { get; set; } = "NULL"; /* 취약점 함수 이름 */
            public string Language { get; set; } = "NULL"; /* 취약점 언어 종류 */
            public string CodeOriBefore { get; set; } = "NULL"; /* 취약점 패치 전 원본 코드 */
            public string CodeOriAfter { get; set; } = "NULL"; /* 취약점 패치 후 원본 코드 */
            public string CodeAbsBefore { get; set; } = "NULL"; /* 취약점 패치 전 추상화 코드 */
            public string CodeAbsAfter { get; set; } = "NULL"; /* 취약점 패치 후 추상화 코드 */
            public string BlockHash { get; set; } = "NULL";/* 취약점 블록 해시 값 */
            public int BlockNum { get; set; } = -1; /* 블록 번호 */
            // 생성자
            public Vuln()
            {
            }
            public Vuln(int _lenBlock, string _repositName, string _cve, string _funcName, string _language, string _codeOriBefore, string _codeOriAfter, string _codeAbsBefore, string _codeAbsAfter, string _blockHash)
            {
                //임의의 VulnId 
                VulnId = -1;
                LenBlock = _lenBlock;
                RepositName = _repositName;
                Cve = _cve;
                FuncName = _funcName;
                Language = _language;
                CodeOriBefore = _codeOriBefore;
                CodeOriAfter = _codeOriAfter;
                CodeAbsBefore = _codeAbsBefore;
                CodeAbsAfter = _codeAbsAfter;
                BlockHash = _blockHash;
            }
            public Vuln(int _vulnId, int _lenBlock, string _repositName, string _cve, string _funcName, string _language, string _codeOriBefore, string _codeOriAfter, string _codeAbsBefore, string _codeAbsAfter, string _blockHash)
            {
                VulnId = _vulnId;
                LenBlock = _lenBlock;
                RepositName = _repositName;
                Cve = _cve;
                FuncName = _funcName;
                Language = _language;
                CodeOriBefore = _codeOriBefore;
                CodeOriAfter = _codeOriAfter;
                CodeAbsBefore = _codeAbsBefore;
                CodeAbsAfter = _codeAbsAfter;
                BlockHash = _blockHash;
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
            public User(int _UserId, string _RepositName, string _Cve, string _CodeOriBefore, string _CodeOriAfter, string _FuncName, string _DetectDate)
            {
                UserId = _UserId;
                RepositName = _RepositName;
                Cve = _Cve;
                CodeOriBefore = _CodeOriBefore;
                CodeOriAfter = _CodeOriAfter;
                FuncName = _FuncName;
                DetectDate = _DetectDate;
            }
        }
        //connect
        public static void Connect(AWS.Account account, string dbName)
        {
            MySqlConnectionStringBuilder builder = new MySqlConnectionStringBuilder()
            {
                Server = account.Endpoint,
                UserID = account.Id,
                Password = account.Pw,
                Database = dbName,
                Port = 3306,
            };
            string strConn = builder.ToString();
            builder = null;
            Conn = new MySqlConnection(strConn);
            Conn.Open();
            Account = account;
            DbName = dbName;
        }
        public static void InsertVulnData(Vuln vuln)
        {
            //  Conn.Open();
            //DB에 취약점 데이터가 이미 있는지 검사
            String sql = string.Empty;
            //String sql = "select count(*) from vulnInfo where cve like '" + vuln.Cve + "'";
            //MySqlCommand cmd = new MySqlCommand(sql, Conn);


            //int RecordCount = Convert.ToInt32(cmd.ExecuteScalar());
            ////CVE 중복인 경우
            //if (RecordCount > 0)
            //{
            //    Console.WriteLine("이미 cve가 존재함");
            //}
            //CVE 중복이 아닌 경우
            //else
            //{
            // vulnId setting  (마지막 vulnId +1)
            MySqlCommand cmd = null;

            int last_vulnId = 1;
            try
            {
                sql = "select max(vulnId) from vulnInfo";
                cmd = new MySqlCommand(sql, Conn);

                last_vulnId = (Convert.ToInt32(cmd.ExecuteScalar())) + 1;
            }
            catch(Exception)
            {
                last_vulnId = 1;
            }
 
            Retry:

            //DB insert
            try
            {
                sql = "INSERT INTO vulnInfo(vulnId, lenBlock, repositName, cve, funcName, numBlock, codeOriBefore, codeOriAfter, codeAbsBefore, codeAbsAfter, blockHash) " +
                       $"VALUES({last_vulnId}, {vuln.LenBlock}, '{vuln.RepositName}', '{vuln.Cve}', '{vuln.FuncName}', {vuln.BlockNum}, '{vuln.CodeOriBefore}', '{vuln.CodeOriAfter}', '{vuln.CodeAbsBefore}', '{vuln.CodeAbsAfter}', '{vuln.BlockHash}')";
                //sql = "INSERT INTO vulnInfo (vulnId, lenBlock, repositName, cve, funcName, codeOriBefore, codeOriAfter, codeAbsBefore, codeAbsAfter, blockHash) " +
                //       "VALUES(" + last_vulnId + ", " + vuln.LenBlock + ", " + vuln.RepositName + ", " + vuln.Cve + ", " + vuln.FuncName + ", " + vuln.CodeOriBefore + ", " + vuln.CodeOriAfter + ", " + vuln.CodeAbsBefore + ", " + vuln.CodeAbsAfter + ", '" + vuln.BlockHash + "')";
                Console.WriteLine(sql);
               // cmd = new MySqlCommand(sql, Conn);
               // cmd.ExecuteNonQuery();
                //Conn.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                string es = e.ToString();
                if (es.Contains("Connection must be valid and open"))
                {
                    Connect(Account, DbName);
                    goto Retry;
                }
                Console.ReadLine();
            }
            // }
        }
        public static void InsertUserData(User user)
        {
            Conn.Open();
            //DB에 취약점 데이터가 이미 있는지 검사
            String sql = "select count(*) from vulnInfo where cve like '" + user.Cve + "'";
            MySqlCommand cmd = new MySqlCommand(sql, Conn);
            int RecordCount = Convert.ToInt32(cmd.ExecuteScalar());
            //CVE 중복인 경우
            if (RecordCount > 0)
            {
                Console.WriteLine("이미 cve가 존재함");
            }
            //CVE 중복이 아닌 경우
            else
            {
                //DB insert
                try
                {
                    sql = "INSERT INTO userInfo (userId, repositName, cve,codeOriBefore,codeOriAfter,funcName,detectDate) " +
                           "VALUES(" + user.UserId + "," + user.RepositName + "," + user.Cve + "," + user.CodeOriBefore + "," + user.CodeOriAfter + "," + user.FuncName + "," + user.DetectDate + ")";
                    cmd = new MySqlCommand(sql, Conn);
                    cmd.ExecuteNonQuery();
                    Conn.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.StackTrace);
                }
            }
        }
        public static Vuln SearchVulnCve(string _cve)
        {
            Vuln vuln = new Vuln();
            Conn.Open();
            //특정 cve 가 있는지 검사
            String sql = "select * from vulnInfo where cve like '" + _cve + "'";
            MySqlCommand cmd = new MySqlCommand(sql, Conn);
            MySqlDataReader rdr = cmd.ExecuteReader();
            while (rdr.Read())
            {
                vuln.VulnId = Convert.ToInt32(rdr["vulnId"]);
                vuln.LenBlock = Convert.ToInt32(rdr["lenBlock"]);
                vuln.RepositName = Convert.ToString(rdr["repositName"]);
                vuln.Cve = Convert.ToString(rdr["cve"]);
                vuln.FuncName = Convert.ToString(rdr["funcName"]);
                vuln.Language = Convert.ToString(rdr["language"]);
                vuln.CodeOriBefore = Convert.ToString(rdr["codeOriBefore"]);
                vuln.CodeOriAfter = Convert.ToString(rdr["codeOriAfter"]);
                vuln.CodeAbsBefore = Convert.ToString(rdr["codeAbsBefore"]); ;
                vuln.CodeAbsAfter = Convert.ToString(rdr["codeAbsAfter"]);
                vuln.BlockHash = Convert.ToString(rdr["blockHash"]);
            }
            Conn.Close();
            return vuln;
        }
        public static int ReturnUserLastId()
        {
            Conn.Open();
            String sql = "select max(userId) from userInfo";
            MySqlCommand cmd = new MySqlCommand(sql, Conn);
            int last_userId = (Convert.ToInt32(cmd.ExecuteScalar())) + 1;
            Conn.Close();
            return last_userId;
        }

        //public static IEnumerable<string> SearchVulnData(int _len)
        //{
        //
        //}
    }
}