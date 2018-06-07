
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using VulnCrawler;

namespace VulnUserCodeAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            var hashDict = new Dictionary<int, HashSet<VulnAbstractCrawler.UserBlock>>();

            DirectoryInfo dirInfo = new DirectoryInfo(@"c:\code");
            var codeFiles = dirInfo.EnumerateFiles("*.c", SearchOption.AllDirectories);
            int totalFileCount = codeFiles.Count();
            var crawler = new VulnC();
            int count = 0;
            foreach (var codeFile in codeFiles)
            {
                Console.WriteLine(codeFile.FullName);
                using (var reader = codeFile.OpenText())
                {

                    var dict = crawler.CrawlUserCode(reader);

                    foreach (var item in dict)
                    {
                        if (!hashDict.ContainsKey(item.Key))
                        {
                            hashDict[item.Key] = new HashSet<VulnAbstractCrawler.UserBlock>();
                        }
                        foreach (var hash in item.Value)
                        {
                            hash.Path = codeFile.FullName;
                            hashDict[item.Key].Add(hash);
                        }
                    }

                    count++;
                    double per = ((double)count / (double)totalFileCount) * 100;

                    Console.Clear();
                    Console.WriteLine($"{count} / {totalFileCount} :: {per.ToString("#0.0")}%, 개체 수 : {hashDict.Count}");

                    //if (count > 20)
                    //{
                    //    break;
                    //}
                }


            }

            foreach (var set in hashDict)
            {
                Console.WriteLine($"-----key:{set.Key}");
                foreach (var hash in set.Value)
                {
                    Console.WriteLine($"{hash.FuncName}, {hash.Hash}, {hash.Len}, {hash.Path}");
                }
            }



        }
    }

}
