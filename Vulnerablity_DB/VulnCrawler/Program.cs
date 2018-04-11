using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MySql.Data.MySqlClient;
namespace VulnCrawler
{
    class Program
    {
        static void Main(string[] args) {

            AWS.SaveAccount();


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
            
//            Run();

        }

        public static void Run() {
            // Repository 폴더들이 있는 주소를 지정하면 하위 폴더 목록을 가져옴(Repository 목록)
            var directorys = Directory.GetDirectories(@"c:\VulnPy");
            if (directorys.Length == 0) {
                Console.WriteLine("Repository 목록 찾기 실패");
                return;
            }
            // Repository 목록 만큼 반복함.
            foreach (var directory in directorys) {
                var pyCrawl = new VulnPython(directory);
                var commits = pyCrawl.Commits;

                
                foreach (var commit in commits) {
                    // 커밋 메시지
                    string message = commit.Message;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Commit Message: {message}");
                    Console.ResetColor();

                    foreach (var parent in commit.Parents) {
                        // 부모 커밋과 현재 커밋을 Compare 하여 패치 내역을 가져옴
                        var patch = pyCrawl.Repository.Diff.Compare<Patch>(parent.Tree, commit.Tree);
                        // 패치 엔트리 파일 배열 중에 파일 확장자가 .py인 것만 가져옴
                        // (실질적인 코드 변경 커밋만 보기 위해서)
                        var entrys = pyCrawl.GetPatchEntryChanges(patch);
                        // 현재 커밋에 대한 패치 엔트리 배열을 출력함
                        PrintPatchEntrys(entrys, pyCrawl);


                    }
                }
            }
        }
                  
        public static void PrintPatchEntrys(IEnumerable<PatchEntryChanges> entrys, VulnAbstractCrawler pyCrawl) {

            foreach (var entry in entrys) {

                // 현재 패치 엔트리 정보 출력(추가된 줄 수, 삭제된 줄 수, 패치 이전 경로, 패치 후 경로)
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"status: {entry.Status.ToString()}");
                Console.WriteLine($"added: {entry.LinesAdded.ToString()}, deleted: {entry.LinesDeleted.ToString()}");
                Console.WriteLine($"old path: {entry.OldPath.ToString()}, new path: {entry.Path.ToString()}");
                Console.ResetColor();

                // 기존 소스코드
                var oldOid = entry.OldOid;
                Blob oldBlob = pyCrawl.Repository.Lookup<Blob>(oldOid);
                string oldContent = oldBlob.GetContentText();

                // 변경된 소스코드
                var newOid = entry.Oid;
                Blob newBlob = pyCrawl.Repository.Lookup<Blob>(newOid);
                string newContent = newBlob.GetContentText();

                var regs = pyCrawl.GetMatches(entry.Patch);
                // 패치 전 코드 (oldContent)
                // 패치 후 코드 (newContent)
                // 패치 코드 (entry.Patch)
                // 출력
                //if (regs.Count > 0) {
                //    Console.BackgroundColor = ConsoleColor.DarkBlue;
                //    Console.WriteLine($"Old Content: \n{oldContent}");
                //    Console.ResetColor();

                //    Console.BackgroundColor = ConsoleColor.DarkMagenta;
                //    Console.WriteLine($"New Content: \n{newContent}");
                //    Console.ResetColor();
                //    Console.BackgroundColor = ConsoleColor.DarkRed;
                //    Console.WriteLine($"Patched: \n{entry.Patch}");

                //    Console.ResetColor();
                //    Console.WriteLine("-----------");
                //    Console.WriteLine(regs.Count);

                //}

                // 패치 코드에서 매칭된 파이썬 함수들로부터 
                // 패치 전 코드 파일(oldBlob)을 탐색하여 원본 파이썬 함수 가져오고(originalFunc)
                // 
                foreach (var reg in regs) {
                    var match = reg as Match;
                    string methodName = match.Groups[VulnAbstractCrawler.MethodName].Value;

                    string originalFunc, md5;

                    (originalFunc, md5) = pyCrawl.GetPatchResult(oldBlob.GetContentStream(),
                        match.Groups[VulnAbstractCrawler.MethodName].Value);
      
                    // 패치 전 원본 함수
                    Console.WriteLine($"Original Func: {originalFunc}");
                    // 해쉬 후
                    Console.WriteLine($"Original Func MD5: {md5}");



                }
            }
        }

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

        /// <summary>
        /// Clone 콜백 함수
        /// </summary>
        /// <param name="progress"></param>
        /// <returns></returns>
        public static bool TransferProgress(TransferProgress progress) {
            int totalBytes = progress.TotalObjects;
            int receivedBytes = progress.ReceivedObjects;
            long receivedTotal = progress.ReceivedBytes;
            double received = progress.ReceivedBytes / 1000000;
            double percent = ((double)receivedBytes / (double)totalBytes) * 10;

            Console.WriteLine($"진행률: {percent.ToString("P2")}, 남은 파일: {receivedBytes} of {totalBytes}"); //, 받은 용량: {received.ToString()}MB");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            return true;
        }

        public static void CheckoutProcess(string path, int completedSteps, int totalSteps) {
            Console.WriteLine($"{completedSteps}, {totalSteps}, {path}");
        }


    }
}
