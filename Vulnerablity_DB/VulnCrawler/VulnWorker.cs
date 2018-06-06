
using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.IO;
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
            /* Git 경로로 초기화 */
            crawler.Init(dirPath);
            /* 초기화된 커밋 목록 가져옴 */
            var commits = crawler.Commits;
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
                    /* C:\VulnC\linux 라면 linux만 뽑아서 repoName에 저장 */
                    var dsp = dirPath.Split(Path.DirectorySeparatorChar);
                    string repoName = dsp[dsp.Length - 1];
                    // 현재 커밋에 대한 패치 엔트리 배열을 출력함
                    PrintPatchEntrys(entrys, crawler, message, cve, repoName);
                  //  Console.ReadLine();
                }
            }
        }

        private static void PrintPatchEntrys(IEnumerable<PatchEntryChanges> entrys, VulnAbstractCrawler self, string commitMsg, string cve, string repoName) {
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
                        int deleted = entry.LinesDeleted;
                        if (deleted == 0)
                        {
                            continue;
                        }
                        Console.BackgroundColor = ConsoleColor.DarkBlue;
                        Console.WriteLine($"Old Content: \n{oldContent}");
                        Console.ResetColor();

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
                        /* 패치된 코드들에서 Method로 나누고 크리티컬 변수로 뽑아옴 Dictionary 구조 (키 = 함수명) */
                        var table = self.ExtractGitCriticalMethodTable(entry.Patch);
                        /* 크리티컬 메서드 테이블과 패치 전 파일에서 Process 하고 tuple로 가져옴 */
                        foreach (var tuple in self.Process(oldBlob, table))
                        {
                            /* 메서드 이름, 원본 함수 코드, 블록 리스트(크리티컬 포함) */
                            (var methodName, var oriFunc, var blocks) = tuple;
                            Console.BackgroundColor = ConsoleColor.DarkRed;
                            Console.WriteLine($"메서드 이름 : {methodName}");
                            Console.ResetColor();
                            foreach (var block in blocks)
                            {
                                /* 크리티컬 블록이 아니면 볼 필요 없으니 넘어감 */
                                if (!block.HasCritical)
                                {
                                    // Console.WriteLine("크리티컬 아님");
                                    continue;
                                }


                                if (block.HasCritical)
                                {
                                    Console.BackgroundColor = ConsoleColor.DarkMagenta;
                                }
                                else
                                {
                                    Console.BackgroundColor = ConsoleColor.DarkGreen;
                                }
                                /* 블록 정보 출력(블록 번호, 블록 소스코드, 블록 추상화 코드, 블록 해쉬값) */
                                Console.WriteLine($"=====block({block.Num}, {block.HasCritical.ToString()})");
                                Console.WriteLine(block.Code);
                                Console.ResetColor();
                                Console.WriteLine($"AbsCode = \n{block.AbsCode}");
                                Console.WriteLine($"MD5 = {block.Hash}");

                                /* base64 인코딩(MySQL에 들어갈 수 없는 문자열이 있을 수 있으므로 인코딩) */
                                byte[] funcNameBytes = Encoding.Unicode.GetBytes(methodName);
                                byte[] codeOriBeforeBytes = Encoding.Unicode.GetBytes(oriFunc);
                                byte[] codeAbsBeforeBytes = Encoding.Unicode.GetBytes(block.AbsCode);

                                /* VulnDB에 하나의 레코드로 들어가는 하나의 취약점 객체 */
                                VulnRDS.Vuln vuln = new VulnRDS.Vuln()
                                {
                                    Cve = cve,
                                    BlockHash = block.Hash,
                                    LenBlock = block.Code.Length,
                                    FuncName = Convert.ToBase64String(funcNameBytes),
                                    CodeOriBefore = Convert.ToBase64String(codeOriBeforeBytes),
                                    CodeAbsBefore = Convert.ToBase64String(codeAbsBeforeBytes),
                                    NumBlock = block.Num,
                                };
                                Console.WriteLine($"Vuln FuncName:{vuln.FuncName}");
                                /* VulnDB에 추가 */
                                VulnRDS.InsertVulnData(vuln);
                            }
                        }
                    }
                    else
                    {
                        continue;
                    }

                    #endregion

                }
                catch (Exception e)
                {
                    continue;
                }

            }
        }

    }
}
