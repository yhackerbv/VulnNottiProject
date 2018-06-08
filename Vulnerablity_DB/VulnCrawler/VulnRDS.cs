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
            public string Cve { get; set; } = "NULL"; /* 취약점 CVE */
            public string FuncName { get; set; } = "NULL"; /* 취약점 함수 이름 */
            public int NumBlock { get; set; } = -1; /* 블록 번호 */
            public string CodeOriBefore { get; set; } = "NULL"; /* 취약점 패치 전 원본 코드 */
            public string CodeOriAfter { get; set; } = "NULL"; /* 취약점 패치 후 원본 코드 */
            public string CodeAbsBefore { get; set; } = "NULL"; /* 취약점 패치 전 추상화 코드 */
            public string CodeAbsAfter { get; set; } = "NULL"; /* 취약점 패치 후 추상화 코드 */
            public string BlockHash { get; set; } = "NULL";/* 취약점 블록 해시 값 */     
        }
        public class User
        {
            public int UserId { get; set; } = -1;/* 유저 ID */
            public string RepositName { get; set; } = "NULL"; /* 유저 레파지토리 이름 */
            public int VulnId { get; set; } = -1; /* 취약점 vuln ID */
        }
        public class _Vuln
        {
            public int VulnId { get; set; } = -1; /* 취약점 ID */
            public string Cve { get; set; } = "NULL"; /* 취약점 CVE */
            public string FuncName { get; set; } = "NULL"; /* 취약점 함수 이름 */
            public int LenFunc { get; set; } = -1; /* 취약점 함수 길이 */
            public string Code { get; set; } = "NULL"; /* 취약점 소스 코드 */
            public string BlockHash { get; set; } = "NULL";/* 취약점 블록 해시 값 */
            public string Url { get; set; } = "NULL"; /* 취약점 URL */

            public override bool Equals(object obj)
            {
                var vuln = obj as _Vuln;
                return vuln != null &&
                       BlockHash == vuln.BlockHash;
            }

            public override int GetHashCode()
            {
                return 802558182 + EqualityComparer<string>.Default.GetHashCode(BlockHash);
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
            String sql = string.Empty;
            MySqlCommand cmd = null;

            // vulnId setting  (마지막 vulnId +1)
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
                sql = "INSERT INTO vulnInfo(vulnId, lenBlock, cve, funcName, numBlock, codeOriBefore, codeOriAfter, codeAbsBefore, codeAbsAfter, blockHash) " +
                       $"VALUES({last_vulnId}, {vuln.LenBlock}, '{vuln.Cve}', '{vuln.FuncName}', {vuln.NumBlock}, '{vuln.CodeOriBefore}', '{vuln.CodeOriAfter}', '{vuln.CodeAbsBefore}', '{vuln.CodeAbsAfter}', '{vuln.BlockHash}')";
                Console.WriteLine(sql);
                cmd = new MySqlCommand(sql, Conn);
                cmd.ExecuteNonQuery();
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

        }
        public static void _InsertVulnData(_Vuln vuln)
        {
            String sql = string.Empty;
            MySqlCommand cmd = null;
            // vulnId setting  (마지막 vulnId +1)
            int last_vulnId = 1;
            try
            {
                sql = "select max(vulnId) from vuln_Info";
                cmd = new MySqlCommand(sql, Conn);
                last_vulnId = (Convert.ToInt32(cmd.ExecuteScalar())) + 1;
            }
            catch (Exception)
            {
                last_vulnId = 1;
            }
            Retry:
            //DB insert
            try
            {
                cmd = new MySqlCommand
                {
                    Connection = Conn,
                    //db에 추가
                    CommandText = "INSERT INTO vuln_Info(vulnId, cve, funcName, lenFunc, code, blockHash, url) VALUES(@vulnId, @cve, @funcName, @lenFunc, @code, @blockHash, @url)"
                };
                cmd.Parameters.AddWithValue("@vulnId", last_vulnId);
                cmd.Parameters.AddWithValue("@cve", $"{vuln.Cve}");
                cmd.Parameters.AddWithValue("@funcName", $"{vuln.FuncName}");
                cmd.Parameters.AddWithValue("@lenFunc", $"{vuln.LenFunc}");
                cmd.Parameters.AddWithValue("@code", $"{vuln.Code}");
                cmd.Parameters.AddWithValue("@blockHash", $"{vuln.BlockHash}");
                cmd.Parameters.AddWithValue("@url", $"{vuln.Url}");
                cmd.ExecuteNonQuery();
                //콘솔출력용
                sql = "INSERT INTO vuln_Info(vulnId, cve, funcName, lenFunc, code, blockHash, url) " +
                       $"VALUES({last_vulnId}, {vuln.Cve}, '{vuln.FuncName}', '{vuln.LenFunc}', {vuln.Code},'{vuln.BlockHash}', '{vuln.Url}')";
                //Console.WriteLine(sql);
                //Console.ReadLine();
                
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
                //Console.ReadLine();
            }
        }
        public static void InsertUserData(User user)
        {
            Conn.Open();
            String sql = string.Empty;
            MySqlCommand cmd = null;

            //user_id setting
            int last_userId = 1;
            try
            {
                sql = "select max(userId) from userInfo";
                cmd = new MySqlCommand(sql, Conn);
                last_userId = (Convert.ToInt32(cmd.ExecuteScalar())) + 1;
            }
            catch (Exception)
            {
                last_userId = 1;
            }

            Retry:

            //insert 
            try
            {
                cmd = new MySqlCommand();
                cmd.Connection = Conn;
                //db에 추가
                cmd.CommandText = "INSERT INTO userInfo(userId, repositName, vulnId) VALUES(@userId, @repositName, @vulnId)";
                cmd.Parameters.AddWithValue("@userId", last_userId);
                cmd.Parameters.AddWithValue("@repositName", $"{user.RepositName}");
                cmd.Parameters.AddWithValue("@vulnInfo", $"{user.VulnId}");
                cmd.ExecuteNonQuery();
                //콘솔출력용
                sql = "INSERT INTO userInfo(userId, repositName, vulnId) " + $"VALUES({last_userId},'{user.RepositName}','{user.VulnId}')";
                Console.WriteLine(sql);
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
        }
        public static void UpdateVulnData(int _vulnId, _Vuln vuln) {
            String sql = string.Empty;
            MySqlCommand cmd = null;

            Retry:

            //DB update
            try
            {
                cmd = new MySqlCommand();
                cmd.Connection = Conn;
                //해당 vuln Update
                cmd.CommandText = "UPDATE vuln_Info SET cve=@cve,funcName=@funcName,lenFunc=@lenFunc,code=@code,blockHash=@blockHash,url=@url WHERE vulnId=@vulnId";
                cmd.Parameters.AddWithValue("@vulnId", _vulnId);
                cmd.Parameters.AddWithValue("@cve", $"{vuln.Cve}");
                cmd.Parameters.AddWithValue("@funcName", $"{vuln.FuncName}");
                cmd.Parameters.AddWithValue("@lenFunc", $"{vuln.LenFunc}");
                cmd.Parameters.AddWithValue("@code", $"{vuln.Code}");
                cmd.Parameters.AddWithValue("@blockHash", $"{vuln.BlockHash}");
                cmd.Parameters.AddWithValue("@url", $"{vuln.Url}");
                cmd.ExecuteNonQuery();
                //콘솔출력용
                sql = "UPDATE vuln_Info(vulnId, cve, funcName, lenFunc, code, blockHash, url) " +
                       $"VALUES({_vulnId}, {vuln.Cve}, '{vuln.FuncName}', '{vuln.LenFunc}', {vuln.Code},'{vuln.BlockHash}', '{vuln.Url}')";
                Console.WriteLine(sql);
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
            return;
        }
        public static void UpdateUserData(int _userId, User user) 
        {
            String sql = string.Empty;
            MySqlCommand cmd = null;

            Retry:

            //DB update
            try
            {
                cmd = new MySqlCommand();
                cmd.Connection = Conn;
                //해당 user Update
                cmd.CommandText = "UPDATE userInfo SET repositName=@repositName, vulnId=@vulnId WHERE userId=@userId";
                cmd.Parameters.AddWithValue("@userId", _userId);
                cmd.Parameters.AddWithValue("@repositName", $"{user.RepositName}");
                cmd.Parameters.AddWithValue("@vulnId", $"{user.VulnId}");
                cmd.ExecuteNonQuery();

                //콘솔출력용
                sql = "UPDATE userInfo(userId, repositName, vulnId) " +
                       $"VALUES({_userId}, '{user.RepositName}', '{user.VulnId}')";
                Console.WriteLine(sql);
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
            return;
        }
        public static _Vuln SelectVulnData(int _vulnId) {
            _Vuln vuln = new _Vuln();

            String sql = string.Empty;
            MySqlCommand cmd = new MySqlCommand();
            cmd.Connection = Conn;
            cmd.CommandText = "SELECT * FROM vuln_Info";

            System.Data.DataSet ds = new System.Data.DataSet();
            MySqlDataAdapter da = new MySqlDataAdapter("SELECT * FROM vuln_Info", Conn);
            da.Fill(ds);

            //vuln에 입력
            foreach (System.Data.DataRow row in ds.Tables[0].Rows)
            {
                vuln.VulnId = Convert.ToInt32(row["vulnId"]);
                vuln.Cve = Convert.ToString(row["cve"]);
                vuln.FuncName = Convert.ToString(row["funcName"]);
                vuln.LenFunc = Convert.ToInt32(row["lenFunc"]);
                vuln.Code = Convert.ToString(row["code"]);
                vuln.BlockHash = Convert.ToString(row["blockHash"]);
                vuln.Url = Convert.ToString(row["url"]);
            }
            //해당 vuln 반환
            return vuln;
        }
        public static User SelectUserData(int _userId)
        {
            User user = new User();
            String sql = string.Empty;
            MySqlCommand cmd = new MySqlCommand();
            cmd.Connection = Conn;
            cmd.CommandText = "SELECT * FROM userInfo";

            //해당 user 찾음
            System.Data.DataSet ds = new System.Data.DataSet();
            MySqlDataAdapter da = new MySqlDataAdapter("SELECT * FROM userInfo", Conn);
            da.Fill(ds);

            //user에 입력
            foreach (System.Data.DataRow row in ds.Tables[0].Rows)
            {
                user.VulnId = Convert.ToInt32(row["vulnId"]);
                user.RepositName = Convert.ToString(row["repositName"]);
                user.UserId = Convert.ToInt32(row["userId"]);
            }
            //해당 user 반환
            return user;
        }
        public static void DeleteVulnData(int _vulnId) {
            String sql = string.Empty;
            MySqlCommand cmd = null;

            Retry:

            //DB insert
            try
            {
                cmd = new MySqlCommand();
                cmd.Connection = Conn;
                cmd.CommandText = "DELETE FROM vuln_Info WHERE vulnId=@vulnId";
                cmd.Parameters.AddWithValue("@vulnId", _vulnId);
                cmd.ExecuteNonQuery();
                //콘솔출력용
                sql = "DELETE FROM vuln_Info WHERE vulnId="+ _vulnId;
                Console.WriteLine(sql);
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
        }
        public static void DeleteUserData(int _userId)
        {
            String sql = string.Empty;
            MySqlCommand cmd = null;

            Retry:

            try
            {
                cmd = new MySqlCommand();
                cmd.Connection = Conn;
                cmd.CommandText = "DELETE FROM userInfo WHERE userId=@userId";
                cmd.Parameters.AddWithValue("@userId", _userId);
                cmd.ExecuteNonQuery();
                //콘솔출력용
                sql = "DELETE FROM userInfo WHERE userId=" + _userId;
                Console.WriteLine(sql);
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
        }
        public static IEnumerable<_Vuln> SelectVulnbyLen(int _lenFunc)
        {
           // var list = new List<_Vuln>();
            String sql = string.Empty;
            MySqlCommand cmd = new MySqlCommand();
            cmd.Connection = Conn;
            cmd.CommandText = "SELECT * FROM vuln_Info where lenFunc=" + _lenFunc;

            System.Data.DataSet ds = new System.Data.DataSet();
            MySqlDataAdapter da = new MySqlDataAdapter("SELECT * FROM vuln_Info where lenFunc=" + _lenFunc, Conn);
            da.Fill(ds);

            //vuln에 입력
            foreach (System.Data.DataRow row in ds.Tables[0].Rows)
            {
                _Vuln vuln = new _Vuln
                {
                    VulnId = Convert.ToInt32(row["vulnId"]),
                    Cve = Convert.ToString(row["cve"]),
                    FuncName = Convert.ToString(row["funcName"]),
                    LenFunc = Convert.ToInt32(row["lenFunc"]),
                    Code = Convert.ToString(row["code"]),
                    BlockHash = Convert.ToString(row["blockHash"]),
                    Url = Convert.ToString(row["url"])
                };
                yield return vuln;
                //list.Add(vuln);
            }
            //해당 list 반환
           // return list;
        }

    }
}