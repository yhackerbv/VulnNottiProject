using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DownloaderGithubClone
{
    using LibGit2Sharp;
    using System.Text.RegularExpressions;

    class Program
    {
        static void Main(string[] args) {

            Console.Write("Git Repository URL을 입력하세요 : ");
            string url = Console.ReadLine();
            //https://github.com/django/django.git

            string pattern = @"https://github.com/(?<ProjectName>\w+)/\w+\.git";

            var match = Regex.Match(url, pattern);

            if (!match.Success) {
                Console.WriteLine($"패턴이 맞지 않습니다. Pattern : {pattern}");
                return;
            }
            string prName = match.Groups["ProjectName"].Value;
            Console.WriteLine(prName);
            

            string clone = Repository.Clone(url, $@"c:\VulnPy\{prName}", new CloneOptions { OnTransferProgress = TransferProgress, OnCheckoutProgress = CheckoutProcess });
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
