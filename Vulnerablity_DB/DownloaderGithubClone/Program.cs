using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DownloaderGithubClone
{
  //  using LibGit2Sharp;
    using System.IO;
    using System.Text.RegularExpressions;
    using LibGit2Sharp;
  

    class Program
    {
        static void Main(string[] args) {

            string dir = @"c:\VulnPy";
            if (!Directory.Exists(dir)) {
                Directory.CreateDirectory(dir);
                Console.WriteLine($"디렉토리 생성 : {dir}");
            }

            Console.Write("Git Repository URL을 입력하세요 : ");
            string url = Console.ReadLine();
            //https://github.com/django/django.git
            string pattern = @"https://github.com/.+/(?<ProjectName>.+)\.(.+)";
            var match = Regex.Match(url, pattern);
            if (!match.Success) {
                Console.WriteLine($"패턴이 맞지 않습니다. Pattern : {pattern}");
                return;
            }
            string prName = match.Groups["ProjectName"].Value;
            Console.WriteLine(prName);
            int idx = 1;
            string path = Path.Combine(dir, prName);
            if (Directory.Exists(path)) {
                while (true) {
                    path = Path.Combine(dir, prName + idx);
                    if (!Directory.Exists(path)) {
                        Directory.CreateDirectory(path);
                        Console.WriteLine($"레파지토리 디렉토리 생성 : {path}");
                        break;
                    }
                }
            }

            Console.WriteLine($"다운로드를 진행합니다. 경로 : {path}");


            string clone = Repository.Clone(url, $@"{path}", new CloneOptions { OnTransferProgress = TransferProgress, OnCheckoutProgress = CheckoutProcess });
            Console.ResetColor();
            Console.WriteLine(clone);
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
            double percent = ((double)receivedBytes / (double)totalBytes);

            Console.WriteLine($"진행률: {percent.ToString("P2")}, 남은 파일: {receivedBytes} of {totalBytes}"); //, 받은 용량: {received.ToString()}MB");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            return true;
        }

       
        public static void CheckoutProcess(string path, int completedSteps, int totalSteps) {
            Console.WriteLine($"{completedSteps}, {totalSteps}, {path}");
        }


    }
}
