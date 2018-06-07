
using BloomFilter;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            var crawler = new VulnC();
            //var bytes = Convert.FromBase64String("dgBvAGkAZAAgAGsAdgBtAF8AbQBtAHUAXwBuAGUAdwBfAGMAcgAzACgAcwB0AHIAdQBjAHQAIABrAHYAbQBfAHYAYwBwAHUAIAAqAHYAYwBwAHUAKQANAAoAewANAAoACQBtAG0AdQBfAGYAcgBlAGUAXwByAG8AbwB0AHMAKAB2AGMAcAB1ACkAOwANAAoAfQANAAoA");
            //var str = Encoding.Unicode.GetString(bytes);

            //Console.WriteLine(str);
            //Console.WriteLine(crawler.Abstract(str, new Dictionary<string, string>(), new Dictionary<string, string>()));
            //Console.ReadLine();

            // default usage
            int capacity = 50000000;
            var filter = new Filter<string>(capacity);

            /* AWS 계정 정보 파일 읽음 */
            string txt = File.ReadAllText(@"Account.xml");
            // string xml = aes.AESDecrypt128(txt, key);
            string xml = txt;

            AWS.LoadAccount(xml);
            AWS.Account account = AWS.account;

            /* AWS 정보 출력 */
            Console.WriteLine($"Endpoint: {account.Endpoint}, ID: {account.Id}, PW: {account.Pw}");
            try
            {
                /* DB 접속 시도 */
                VulnRDS.Connect(account, "vuln");
            }
            catch (Exception e)
            {
                Console.WriteLine($"접속 에러 :: {e.ToString()}");
                return;
            }

            /* AWS 연결 여부 확인 */
            if (VulnRDS.Conn.State == System.Data.ConnectionState.Open)
            {
                Console.WriteLine("접속 성공");

            }
            else
            {
                Console.WriteLine("연결 실패");
                return;
            }

            var hashDict = new Dictionary<int, HashSet<VulnAbstractCrawler.UserBlock>>();

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            DirectoryInfo dirInfo = new DirectoryInfo(@"c:\code");
            var codeFiles = dirInfo.EnumerateFiles("*.c", SearchOption.AllDirectories);
            int totalFileCount = codeFiles.Count();

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
                            filter.Add(hash.Hash);
                        }
                    }

                    count++;
                    double per = ((double)count / (double)totalFileCount) * 100;

                    Console.Clear();
                    Console.WriteLine($"{count} / {totalFileCount} :: {per.ToString("#0.0")}%, 개체 수 : {hashDict.Count}");

                    if (count > 100)
                    {
                        break;
                    }
                }


            }
            
            var findBlocks = new Queue<VulnAbstractCrawler.UserBlock>();

            foreach (var set in hashDict)
            {
                Console.WriteLine($"-----key:{set.Key}");
                var vulnList = VulnRDS.SelectVulnbyLen(set.Key);
                foreach (var vuln in vulnList)
                {
                //    Console.WriteLine(vuln.BlockHash);
                    if (filter.Contains(vuln.BlockHash))
                    {
                        Console.WriteLine($"필터 확인 : {vuln.BlockHash}");
                        if (hashDict.ContainsKey(vuln.LenFunc))
                        {
                            var userBlock = hashDict[vuln.LenFunc].FirstOrDefault(b => b.Hash == vuln.BlockHash);
                            if (userBlock == null)
                            {
                                Console.WriteLine("userBlock이 비어있습니다.");
                                continue;
                            }
                            Console.WriteLine($"CVE:{vuln.Cve}, {userBlock.FuncName}, 블록 확인 : DB : {vuln.BlockHash}, User : {userBlock.Hash}");
                            findBlocks.Enqueue(userBlock);
                        }
                    }

                }
                //foreach (var hash in set.Value)
                //{

                //    Console.WriteLine($"{hash.FuncName}, {hash.Hash}, {hash.Len}, {hash.Path}");
                //}
            }

            stopwatch.Stop();




            var hours = stopwatch.Elapsed.TotalHours;
            var minutes = stopwatch.Elapsed.TotalMinutes;
            var seconds = stopwatch.Elapsed.TotalSeconds;

            Console.WriteLine($"경과 시간 {hours.ToString("00")}:{minutes.ToString("00")}:{seconds.ToString("00")}");


            // 블룸 필터 테스트
            //while(true)
            //{
            //    string key = Console.ReadLine();
            //    if (key == "-1")
            //    {
            //        break;
            //    }
            //    if (filter.Contains(key))
            //    {
            //        Console.WriteLine("포함");
            //    }
            //    else
            //    {
            //        Console.WriteLine("없음");
            //    }

                
            //}


        }
    }

}
