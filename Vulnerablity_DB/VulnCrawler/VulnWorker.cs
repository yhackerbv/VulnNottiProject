
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
            int totalCount = commits.Count();
            int count = 0;
            string dir = Path.Combine(dirPath, "url.txt");

            if (File.Exists(dir))
            {
                crawler.PushUrl = File.ReadAllText(dir);
            }
            foreach (var commit in commits) {
                // 커밋 메시지
                
                count++;
                double per = ((double)count / (double)totalCount) * 100;

                Console.Clear();
                Console.WriteLine($"{count} / {totalCount} :: {per.ToString("#0.0")}%");
                
                string message = commit.Message;
                string cve = crawler.GetCVE(message);
                if (string.IsNullOrEmpty(cve)) {
                    continue;
                }

                string commitUrl = $"{crawler.PushUrl}/commit/{commit.Sha}";

                foreach (var parent in commit.Parents) {

                    try
                    {
                        // 부모 커밋과 현재 커밋을 Compare 하여 패치 내역을 가져옴
                        var patch = crawler.Repository.Diff.Compare<Patch>(parent.Tree, commit.Tree);
                        // 패치 엔트리 파일 배열 중에 파일 확장자가 .py인 것만 가져옴
                        // (실질적인 코드 변경 커밋만 보기 위해서)
                        var entrys = crawler.GetPatchEntryChanges(patch);
                        /* C:\VulnC\linux 라면 linux만 뽑아서 repoName에 저장 */
                        var dsp = dirPath.Split(Path.DirectorySeparatorChar);
                        string repoName = dsp[dsp.Length - 1];
                        // 현재 커밋에 대한 패치 엔트리 배열을 출력함
                        PrintPatchEntrys(entrys, crawler, message, cve, repoName, commitUrl);
                        //  Console.ReadLine();
                    }
                    catch(Exception)
                    { }
                }
            }
        }

        private static void PrintPatchEntrys(IEnumerable<PatchEntryChanges> entrys, VulnAbstractCrawler self, string commitMsg, string cve, string repoName, string commitUrl) {
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
                        /* 패치된 코드들에서 Method로 나누고 크리티컬 변수로 뽑아옴 Dictionary 구조 (키 = 함수명) */
                        var table = self.ExtractGitCriticalMethodTable(entry.Patch);
                        /* 크리티컬 메서드 테이블과 패치 전 파일에서 Process 하고 tuple로 가져옴 */
                        foreach (var tuple in self.Process(oldBlob, table))
                        {
                            /* 메서드 이름, 원본 함수 코드, 블록 리스트(크리티컬 포함) */
                            (var methodName, var oriFunc, var blocks) = tuple;

                            if (string.IsNullOrWhiteSpace(oriFunc))
                            {
                                continue;
                            }

              
                            string abstractCode = self.Abstract(oriFunc, new Dictionary<string, string>(), new Dictionary<string, string>());

                            byte[] funcNameBytes = Encoding.Unicode.GetBytes(methodName);
                            byte[] absCodeBytes = Encoding.Unicode.GetBytes(abstractCode);
                            byte[] commitUrlBytes = Encoding.Unicode.GetBytes(commitUrl);
                            byte[] funcBytes = Encoding.Unicode.GetBytes(oriFunc);

                            string absCodeBase64 = Convert.ToBase64String(absCodeBytes);

                            VulnRDS._Vuln vuln = new VulnRDS._Vuln()
                            {
                                LenFunc = absCodeBase64.Length,
                                Cve = cve,
                                BlockHash =  VulnAbstractCrawler.MD5HashFunc(absCodeBase64),
                                FuncName = Convert.ToBase64String(funcNameBytes),
                                Code = Convert.ToBase64String(funcBytes),
                                Url = Convert.ToBase64String(commitUrlBytes),
                            };

                            /* VulnDB에 추가 */
                            VulnRDS._InsertVulnData(vuln);

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
