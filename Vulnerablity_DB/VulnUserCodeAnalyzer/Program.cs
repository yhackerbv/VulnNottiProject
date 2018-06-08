
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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace VulnUserCodeAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            //string json = File.ReadAllText(@"C:\Users\haena\Downloads\cvelist-master\2018\5xxx\CVE-2018-5004.json");
            //JObject jobj = JObject.Parse(json);
            //Console.WriteLine(jobj["CVE_data_meta"].ToString());


            var crawler = new VulnC();
            //var bytes = Convert.FromBase64String("cwB0AGEAdABpAGMAIABpAG4AdAAgAGMAaABhAGMAaABhADIAMABfAHAAbwBsAHkAMQAzADAANQBfAGMAaQBwAGgAZQByACgARQBWAFAAXwBDAEkAUABIAEUAUgBfAEMAVABYACAAKgBjAHQAeAAsACAAdQBuAHMAaQBnAG4AZQBkACAAYwBoAGEAcgAgACoAbwB1AHQALAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBvAG4AcwB0ACAAdQBuAHMAaQBnAG4AZQBkACAAYwBoAGEAcgAgACoAaQBuACwAIABzAGkAegBlAF8AdAAgAGwAZQBuACkADQAKAHsADQAKACAAIAAgACAARQBWAFAAXwBDAEgAQQBDAEgAQQBfAEEARQBBAEQAXwBDAFQAWAAgACoAYQBjAHQAeAAgAD0AIABhAGUAYQBkAF8AZABhAHQAYQAoAGMAdAB4ACkAOwANAAoAIAAgACAAIABzAGkAegBlAF8AdAAgAHIAZQBtACwAIABwAGwAZQBuACAAPQAgAGEAYwB0AHgALQA+AHQAbABzAF8AcABhAHkAbABvAGEAZABfAGwAZQBuAGcAdABoADsADQAKACAAIAAgACAAcwB0AGEAdABpAGMAIABjAG8AbgBzAHQAIAB1AG4AcwBpAGcAbgBlAGQAIABjAGgAYQByACAAegBlAHIAbwBbAFAATwBMAFkAMQAzADAANQBfAEIATABPAEMASwBfAFMASQBaAEUAXQAgAD0AIAB7ACAAMAAgAH0AOwANAAoAIAAgACAAIABpAGYAIAAoACEAYQBjAHQAeAAtAD4AbQBhAGMAXwBpAG4AaQB0AGUAZAApACAAewANAAoAIAAgACAAIAAgACAAIAAgAGEAYwB0AHgALQA+AGsAZQB5AC4AYwBvAHUAbgB0AGUAcgBbADAAXQAgAD0AIAAwADsADQAKACAAIAAgACAAIAAgACAAIABtAGUAbQBzAGUAdAAoAGEAYwB0AHgALQA+AGsAZQB5AC4AYgB1AGYALAAgADAALAAgAHMAaQB6AGUAbwBmACgAYQBjAHQAeAAtAD4AawBlAHkALgBiAHUAZgApACkAOwANAAoAIAAgACAAIAAgACAAIAAgAEMAaABhAEMAaABhADIAMABfAGMAdAByADMAMgAoAGEAYwB0AHgALQA+AGsAZQB5AC4AYgB1AGYALAAgAGEAYwB0AHgALQA+AGsAZQB5AC4AYgB1AGYALAAgAEMASABBAEMASABBAF8AQgBMAEsAXwBTAEkAWgBFACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABhAGMAdAB4AC0APgBrAGUAeQAuAGsAZQB5AC4AZAAsACAAYQBjAHQAeAAtAD4AawBlAHkALgBjAG8AdQBuAHQAZQByACkAOwANAAoAIAAgACAAIAAgACAAIAAgAFAAbwBsAHkAMQAzADAANQBfAEkAbgBpAHQAKABQAE8ATABZADEAMwAwADUAXwBjAHQAeAAoAGEAYwB0AHgAKQAsACAAYQBjAHQAeAAtAD4AawBlAHkALgBiAHUAZgApADsADQAKACAAIAAgACAAIAAgACAAIABhAGMAdAB4AC0APgBrAGUAeQAuAGMAbwB1AG4AdABlAHIAWwAwAF0AIAA9ACAAMQA7AA0ACgAgACAAIAAgACAAIAAgACAAYQBjAHQAeAAtAD4AawBlAHkALgBwAGEAcgB0AGkAYQBsAF8AbABlAG4AIAA9ACAAMAA7AA0ACgAgACAAIAAgACAAIAAgACAAYQBjAHQAeAAtAD4AbABlAG4ALgBhAGEAZAAgAD0AIABhAGMAdAB4AC0APgBsAGUAbgAuAHQAZQB4AHQAIAA9ACAAMAA7AA0ACgAgACAAIAAgACAAIAAgACAAYQBjAHQAeAAtAD4AbQBhAGMAXwBpAG4AaQB0AGUAZAAgAD0AIAAxADsADQAKACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAUABvAGwAeQAxADMAMAA1AF8AVQBwAGQAYQB0AGUAKABQAE8ATABZADEAMwAwADUAXwBjAHQAeAAoAGEAYwB0AHgAKQAsACAAaQBuACwAIABsAGUAbgApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGEAYwB0AHgALQA+AGwAZQBuAC4AYQBhAGQAIAArAD0AIABsAGUAbgA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABhAGMAdAB4AC0APgBhAGEAZAAgAD0AIAAxADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAAbABlAG4AOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABpAGYAIAAoACgAcgBlAG0AIAA9ACAAKABzAGkAegBlAF8AdAApAGEAYwB0AHgALQA+AGwAZQBuAC4AYQBhAGQAIAAlACAAUABPAEwAWQAxADMAMAA1AF8AQgBMAE8AQwBLAF8AUwBJAFoARQApACkADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABQAG8AbAB5ADEAMwAwADUAXwBVAHAAZABhAHQAZQAoAFAATwBMAFkAMQAzADAANQBfAGMAdAB4ACgAYQBjAHQAeAApACwAIAB6AGUAcgBvACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFAATwBMAFkAMQAzADAANQBfAEIATABPAEMASwBfAFMASQBaAEUAIAAtACAAcgBlAG0AKQA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGEAYwB0AHgALQA+AGEAYQBkACAAPQAgADAAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoA");
            //var str = Encoding.Unicode.GetString(bytes);

            //Console.WriteLine(str);
            //var abs = crawler.Abstract(str, new Dictionary<string, string>(), new Dictionary<string, string>());
            //Console.WriteLine(abs);
            //Console.WriteLine(VulnAbstractCrawler.MD5HashFunc(abs));
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
            DirectoryInfo dirInfo = new DirectoryInfo(@"C:\code");
            var codeFiles = dirInfo.EnumerateFiles("*.c", SearchOption.AllDirectories);
            int totalFileCount = codeFiles.Count();
            int count = 0;
            foreach (var codeFile in codeFiles)
            {
               // Process.Start(codeFile.FullName);
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
                    //Console.Clear();
                    Console.WriteLine($"{count} / {totalFileCount} :: {per.ToString("#0.0")}%, 개체 수 : {hashDict.Count}");
                    //if (count > 100)
                    //{
                    //    break;
                    //}
                }
            }
           // Console.ReadLine();

            var findBlocks = new Queue<VulnAbstractCrawler.UserBlock>();
            var vulnDict = new Dictionary<string, IEnumerable<VulnRDS._Vuln>>();
            foreach (var set in hashDict)
            {
                var cveList = VulnRDS.SelectVulnbyLen(set.Key).Select(v => v.Cve).Distinct();
                foreach (var cve in cveList)
                {
                    if (!vulnDict.ContainsKey(cve))
                    {
                        vulnDict[cve] = new HashSet<VulnRDS._Vuln>();
                        var vulnHashSet = vulnDict[cve] as HashSet<VulnRDS._Vuln>;
                        var searchedCveHashList = VulnRDS.SelectVulnbyCve(cve);
                        Console.WriteLine($"cve:{cve}, {searchedCveHashList.Count()}개 가져옴");
                        foreach (var s in searchedCveHashList)
                        {
                            vulnHashSet.Add(s);
                        }
                        
                    }
                }
            }

            foreach (var vulnSet in vulnDict)
            {
                Console.WriteLine($"-----cve:{vulnSet.Key}");
                bool match = false;
                foreach (var vuln in vulnSet.Value)
                {
                    
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
                            match = true;
                            findBlocks.Enqueue(userBlock);
                        }
                    }
                    else
                    {
                        match = false;
                      //  break;
                    }
                }
                if (match)
                {
                    Console.WriteLine($"CVE 찾음 {vulnSet.Key}");
                }
                else
                {
                    Console.WriteLine("없음");
                }
            }

            stopwatch.Stop();




            var hours = stopwatch.Elapsed.Hours;
            var minutes = stopwatch.Elapsed.Minutes;
            var seconds = stopwatch.Elapsed.Seconds;

            Console.WriteLine($"경과 시간 {hours.ToString("00")}:{minutes.ToString("00")}:{seconds.ToString("00")}");


            // CVE JSON 검색

            foreach (var vuln in findBlocks)
            {

            }

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
