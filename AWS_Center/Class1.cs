using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


// 참고(C# mysql 연결)
#region MySql 연결

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

namespace AWS_Center
{
    public static class VulnRDS
    {
        public class Vuln
        {
            public int Len { get; set; } /* 발견된 취약점 함수 PreFunc 부분의 코드 길이 */
            public string RepoName { get; set; } /* 발견된 레파지토리 이름 */
            public string CveName { get; set; } /* 발견된 CVE 이름 */
            public string FuncName { get; set; } /* 발견된 함수 이름 */
            public string PreFunc { get; set; } /* 발견된 패치 전 원본 코드 */
            public string AfterFunc { get; set; } /* 발견된 패치 후 코드 */
            public int SequenceNumber { get; set; } /* 발견된 같은 취약 함수 내에서 블록 순서 번호 */
            public string Hash { get; set; } /* 발견된 크리티칼 블록 해쉬값 */

            // 생성자
            public Vuln()
            {
                
            }

        
        }
        public static void InsertVulnData(int _len, string _repoName, string _cve, string _funcName,
                                            string _preFunc, string _afterFunc, string _hash)
        {
            /*
             * DB에 취약점 데이터가 이미 있는지 검사해야함
             * 
             */
        }

        public static IEnumerable<string> SearchVulnData(int _len)
        {

        }
    }
}
