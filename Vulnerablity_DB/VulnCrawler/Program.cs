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
    class Program
    {
        static void Main(string[] args) {
            //if (Directory.Exists(@"c:\test")) {
            //    DeleteDirectory(@"c:\test");

            //}

            //var co = new CloneOptions {
            //    OnCheckoutProgress = CheckoutProcess,
            //    OnTransferProgress = TransferProgress,

            //    CredentialsProvider = (_url, _user, _cred) => new UsernamePasswordCredentials { Username = "yhackerbv@gmail.com", Password = "@@GUSwjdaf12@@" }

            //};

            //Repository.Clone("https://github.com/torvalds/linux.git", @"\test\", co);
            using (var r = new Repository(@"c:\test2")) {
                var commits = r.Commits
                    .Where(c => Regex.Match(c.Message, @"CVE-20\d\d-\d{4}", RegexOptions.IgnoreCase).Success)
                    //.Where(c => c.Message.IndexOf("CVE-20",
                    //StringComparison.CurrentCultureIgnoreCase) >= 0)
                    .ToList();
                Console.WriteLine(commits.Count);
                foreach (var commit in commits) {

                    string message = commit.Message;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Commit Message: {message}");
                    Console.ResetColor();
                    foreach (var parent in commit.Parents) {
                        var patch = r.Diff.Compare<Patch>(parent.Tree, commit.Tree, new CompareOptions { });

                        var entrys = patch.Where(e => e.Path.EndsWith(".py"));
                        foreach (var entry in entrys) {

                            Console.ForegroundColor = ConsoleColor.Blue;
                            Console.WriteLine($"status: {entry.Status.ToString()}");
                            Console.WriteLine($"added: {entry.LinesAdded.ToString()}, deleted: {entry.LinesDeleted.ToString()}");
                            Console.WriteLine($"old path: {entry.OldPath.ToString()}, new path: {entry.Path.ToString()}");
                            Console.ResetColor();
                            var oldOid = entry.OldOid;
                            Blob oldBlob = r.Lookup<Blob>(oldOid);
                            string oldContent = oldBlob.GetContentText();

                            var newOid = entry.Oid;
                            Blob newBlob = r.Lookup<Blob>(newOid);
                            string newContent = newBlob.GetContentText();



                            //ContentChanges changes = r.Diff.Compare(oldBlob, newBlob);

                            // Console.WriteLine(changes.Patch);

                            //   @@ -290,8 + 290,12 @@ def i
                            //   @@ -290,8 +290,12 @@ def is_safe_url(url, host=None):
                            var regs = Regex.Matches(entry.Patch, @"@@ \-(?<oldStart>\d+),(?<oldLines>\d+) \+(?<newStart>\d+),(?<newLines>\d+) @@ def (?<methodName>\w+)");



                            if (regs.Count > 0) {
                                Console.BackgroundColor = ConsoleColor.DarkBlue;
                                Console.WriteLine($"Old Content: \n{oldContent}");
                                Console.ResetColor();

                                Console.BackgroundColor = ConsoleColor.DarkMagenta;
                                Console.WriteLine($"New Content: \n{newContent}");
                                Console.ResetColor();


                                Console.BackgroundColor = ConsoleColor.DarkRed;

                                Console.WriteLine($"Patched: \n{entry.Patch}");

                                Console.ResetColor();
                                Console.WriteLine("-----------");
                                Console.WriteLine(regs.Count);

                            }

                            foreach (var reg in regs) {
                                var match = reg as Match;
                                int.TryParse(match.Groups["oldStart"].Value, out int oldStart);
                                int.TryParse(match.Groups["oldLines"].Value, out int oldLines);
                                string methodName = match.Groups["methodName"].Value;

                                Console.WriteLine(match.Groups["oldStart"].Value);
                                Console.WriteLine(match.Groups["oldLines"].Value);
                                Console.WriteLine(match.Groups["newStart"].Value);
                                Console.WriteLine(match.Groups["newLines"].Value);
                                Console.WriteLine(match.Groups["methodName"].Value);
                                StringBuilder oldBuilder = new StringBuilder();
                                using (var reader = new StreamReader(oldBlob.GetContentStream())) {
                                    int readCount = 0;
                                    while (!reader.EndOfStream && readCount <= oldStart + oldLines) {
                                        string line = reader.ReadLine();

                                        if (readCount++ >= oldStart) {
                                            oldBuilder.AppendLine(line);
                                        }
                                    }

                                    //bool found = false;
                                    //while (!reader.EndOfStream) {

                                    //    string line = reader.ReadLine();

                                    //    if (line.Contains(string.Join("def ", methodName))) {

                                    //    }

                                    //    if (found) {

                                    //    }
                                    //}
                                }

                                string replace = Regex.Replace(oldBuilder.ToString(), "\t", "");

                                Console.WriteLine($"Builder: \n{replace}");

                            }
                            Console.WriteLine("-----------");
                            Console.ResetColor();
                        }
                        //Console.WriteLine(patch.Content);
                    }

                    Console.WriteLine($"Commit {commit.Sha} 추출 완료");
                    //  Task.Delay(1000).Wait();
                    //break;
                }
            }
        }
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
