
using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VulnCrawler
{

    public static class VulnWorker
    {
        // 템플릿 메서드 패턴
        public static void Run<T>(string dirPath) where T : VulnAbstractCrawler, new() {
            var crawler = new T();
            crawler.Init(dirPath);
            var commits = crawler.Commits;
            Console.WriteLine(commits.Count());
            foreach (var commit in commits) {
                // 커밋 메시지
                string message = commit.Message;
                string cve = crawler.GetCVE(message);
                if (string.IsNullOrEmpty(cve)) {
                    continue;
                }
                foreach (var parent in commit.Parents) {
                    // 부모 커밋과 현재 커밋을 Compare 하여 패치 내역을 가져옴
                    var patch = crawler.Repository.Diff.Compare<Patch>(parent.Tree, commit.Tree);
                    // 패치 엔트리 파일 배열 중에 파일 확장자가 .py인 것만 가져옴
                    // (실질적인 코드 변경 커밋만 보기 위해서)
                    var entrys = crawler.GetPatchEntryChanges(patch);
                    // 현재 커밋에 대한 패치 엔트리 배열을 출력함
                    PrintPatchEntrys(entrys, crawler, message, cve);
                }
            }
        }
      

        private static void PrintPatchEntrys(IEnumerable<PatchEntryChanges> entrys, VulnAbstractCrawler self, string commitMsg, string cve) {

            foreach (var entry in entrys) {
                // 기존 소스코드
                var oldOid = entry.OldOid;

                try
                {
                    Blob oldBlob = self.Repository.Lookup<Blob>(oldOid);
                    string oldContent = oldBlob.GetContentText();

                    // 변경된 소스코드
                    var newOid = entry.Oid;
                    Blob newBlob = self.Repository.Lookup<Blob>(newOid);
                    string newContent = newBlob.GetContentText();
                    var regs = self.GetMatches(entry.Patch);
                    #region 패치 전 후 코드 출력
                    // 패치 전 코드 (oldContent)
                    // 패치 후 코드 (newContent)
                    // 패치 코드 (entry.Patch)
                    // 출력
                    if (regs.Count > 0)
                    {
                        Console.BackgroundColor = ConsoleColor.DarkBlue;
                        Console.WriteLine($"Old Content: \n{oldContent}");
                        Console.ResetColor();

                        //Console.BackgroundColor = ConsoleColor.DarkMagenta;
                        //Console.WriteLine($"New Content: \n{newContent}");
                        //Console.ResetColor();

                        Console.ForegroundColor = ConsoleColor.Blue;
                        Console.WriteLine($"status: {entry.Status.ToString()}");
                        Console.WriteLine($"added: {entry.LinesAdded.ToString()}, deleted: {entry.LinesDeleted.ToString()}");
                        Console.WriteLine($"old path: {entry.OldPath.ToString()}, new path: {entry.Path.ToString()}");
                        Console.ResetColor();


                        Console.Write($"CVE: ");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write($"{cve}");
                        Console.WriteLine("");
                        Console.ResetColor();
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"Commit Message: {commitMsg}");
                        Console.ResetColor();
                        Console.BackgroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine($"Patched: \n{entry.Patch}");
                        Console.ResetColor();

                        var table = self.ExtractGitCriticalMethodTable(entry.Patch);
                        string originalFunc = string.Empty, md5 = string.Empty;
                        foreach (var tuple in self.Process(oldBlob, table))
                        {
                            Console.WriteLine("===z");
                            (originalFunc, md5) = tuple;
                            // 패치 전 원본 함수
                            Console.WriteLine($"Original Func: {originalFunc}");
                            // 해쉬 후
                            Console.WriteLine($"Original Func MD5: {md5}");

                        }


                        //foreach (var item in table)
                        //{
                        //    Console.WriteLine($"Method : {item.Key}");
                        //    //foreach (var b in item.Value)
                        //    //{
                        //    //    Console.WriteLine($"--{b}");
                        //    //}

                        //}
                        Console.ReadLine();
                    }
                    else
                    {
                        continue;
                    }



                    // 패치 코드에서 매칭된 파이썬 함수들로부터 
                    // 패치 전 코드 파일(oldBlob)을 탐색하여 원본 파이썬 함수 가져오고(originalFunc)
                    // 
                    #endregion

                    //foreach (var reg in regs)
                    //{
                        
                    //    var match = reg as Match;
                    //    string methodName = match.Groups[VulnAbstractCrawler.MethodName].Value.Trim();
                    //    string originalFunc, md5;
                    //    (originalFunc, md5) = self.Process(oldBlob.GetContentStream(),
                    //        methodName);

                        

                    //    #region 현재 패치 엔트리 정보 출력(추가된 줄 수, 삭제된 줄 수, 패치 이전 경로, 패치 후 경로)

                        
                    //    // 패치 전 원본 함수
                    //    Console.WriteLine($"Original Func: {originalFunc}");
                    //    // 해쉬 후
                    //    Console.WriteLine($"Original Func MD5: {md5}");
                    //    //Console.BackgroundColor = ConsoleColor.DarkRed;
                    //    //Console.WriteLine($"Patched: \n{entry.Patch}");

                    //    Console.ResetColor();
                    //    Console.ForegroundColor = ConsoleColor.Red;
                    //    Console.WriteLine("==============================");
                    //    Console.ResetColor();
                    //    #endregion

                    //}
                    //Console.ReadLine();
                }
                catch (Exception e)
                {
                    Console.WriteLine(entry.Patch);
                    Console.WriteLine(e.ToString());
                    Console.ReadLine();
                    continue;
                }

            }
        }

    }
}
