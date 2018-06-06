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
            DirectoryInfo dirInfo = new DirectoryInfo(@"c:\code");
            var codeFiles = dirInfo.EnumerateFiles("*.c", SearchOption.AllDirectories);

            var crawler = new VulnC();
            foreach (var codeFile in codeFiles)
            {
                Console.WriteLine(codeFile.FullName);
                using (var reader = codeFile.OpenText())
                {

                    var dict = crawler.CrawlUserCode(reader);

                    foreach (var item in dict)
                    {
                        Console.WriteLine($"----{item.Key}->");
                        foreach (var hash in item.Value)
                        {
                            Console.WriteLine(hash);
                        }
                    }
                }
            }


        }
    }
}
