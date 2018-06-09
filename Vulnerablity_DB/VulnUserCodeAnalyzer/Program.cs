
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
    public class CVE
    {
        public string Type { get; set; }
        public int Year { get; set; }
        //public string UserName { get; set; }
        public string Code { get; set; }
        public DateTime Publish_Date { get; set; }
        public DateTime Update_Date { get; set; }
        public string Detail { get; set; }
        //public string FileName { get; set; }
        //public string FuncNameBase64 { get; set; }
        //public string Url { get; set; }
        public double Level { get; set; }
    }
    public static class CVE_JSON
    {
        /// <summary>
        /// CVE 테이블
        /// </summary>
        public static Dictionary<int, Dictionary<string, CVE>> CveDict { get; set; }
        static CVE_JSON()
        {
            CveDict = new Dictionary<int, Dictionary<string, CVE>>();
        }
        public static void AutoLoad()
        {
            var dir = new DirectoryInfo(@"c:\CVE");

            foreach (var json in dir.EnumerateFiles("*.json"))
            {
                var match = Regex.Match(json.Name, @"(20\d\d)");
                if (!match.Success)
                {
                    continue;
                }
                int year = int.Parse(match.Value);
  
                if (CveDict.ContainsKey(year))
                {
                    continue;
                }
                var dict = LoadCveJson(int.Parse(match.Value));
                CveDict.Add(year, dict);

                Console.WriteLine($"cve 로드 완료 {year}, 개수 : {CveDict[year].Count}");

            }
        }

        /// <summary>
        /// CVE 정보 수집
        /// </summary>
        /// <param name="year"></param>
        /// <returns></returns>
        private static Dictionary<string, CVE> LoadCveJson(int year)
        {
            string json = File.ReadAllText($@"C:\CVE\{year}.json");
            JObject jobj = JObject.Parse(json);
            var cveDict = jobj["CVE_Items"].ToDictionary(t => t["cve"]["CVE_data_meta"]["ID"].ToString(), t =>
            {
                var vendor_data = t["cve"]["affects"]["vendor"]["vendor_data"] as JArray;
                string vendor_name = "NULL";
                if (vendor_data.Count > 0)
                {
                    vendor_name = vendor_data.First()["vendor_name"].ToString();
                }
                var description_data = t["cve"]["description"]["description_data"] as JArray;
                string description = "NULL";
                if (description_data.Count > 0)
                {
                    description = description_data.First()["value"].ToString();
                }
                double level = 0;
                var impact = t["impact"];
                if (impact.HasValues)
                {
                    level = Double.Parse(impact["baseMetricV2"]["cvssV2"]["baseScore"].ToString());
                }
                return new CVE
                {
                    Code = t["cve"]["CVE_data_meta"]["ID"].ToString(),
                    Type = vendor_name,
                    Detail = description,
                    Year = year,
                    Publish_Date = DateTime.Parse(t["publishedDate"].ToString()),
                    Update_Date = DateTime.Parse(t["lastModifiedDate"].ToString()),
                    Level = level,
                };
            });
            return cveDict;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            CVE_JSON.AutoLoad();

            var crawler = new VulnC();

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
                    Console.WriteLine($"{count} / {totalFileCount} :: {per.ToString("#0.0")}%, 개체 수 : {hashDict.Count}");
                }
            }
            //Console.ReadLine();

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
            var findCveDict = new Dictionary<string, List<VulnAbstractCrawler.UserBlock>>();
            var findCveList = new HashSet<string>();
            foreach (var vulnSet in vulnDict)
            {
                //Console.WriteLine($"-----cve:{vulnSet.Key}");
                bool match = false;
                foreach (var vuln in vulnSet.Value)
                {
                    if (filter.Contains(vuln.BlockHash))
                    {
                       // Console.WriteLine($"필터 확인 : {vuln.BlockHash}");
                        if (hashDict.ContainsKey(vuln.LenFunc))
                        {
                            var userBlock = hashDict[vuln.LenFunc].FirstOrDefault(b => b.Hash == vuln.BlockHash);
                            if (userBlock == null)
                            {
                                //Console.WriteLine("userBlock이 비어있습니다.");
                                continue;
                            }
                            if (!findCveDict.ContainsKey(vuln.Cve))
                            {
                                findCveDict[vuln.Cve] = new List<VulnAbstractCrawler.UserBlock>();
                            }
                            userBlock.Url = vuln.Url;
                            findCveDict[vuln.Cve].Add(userBlock);
                            //Console.WriteLine($"CVE:{vuln.Cve}, {userBlock.FuncName}, 블록 확인 : DB : {vuln.BlockHash}, User : {userBlock.Hash}");
                            match = true;
                        }
                    }
                    else
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    Console.WriteLine($"CVE 찾음 {vulnSet.Key}");

                    findCveList.Add(vulnSet.Key);
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
            Console.WriteLine($"찾은 CVE 개수 : {findCveList.Count}");

            var yearMatch = new Regex(@"CVE-(\d{4})-(\d+)");
            foreach (var cve in findCveList)
            {
                Console.WriteLine(cve);

                var c = yearMatch.Match(cve);

                int year = int.Parse(c.Groups[1].Value);

                if (!CVE_JSON.CveDict.ContainsKey(year))
                {
                    continue;
                }
                if (!CVE_JSON.CveDict[year].ContainsKey(cve))
                {
                    continue;
                }
                var data = CVE_JSON.CveDict[year][cve];
                VulnRDS.InsertVulnDetail(new VulnRDS.Vuln_detail
                {
                    CveName = data.Code,
                    Type = data.Type,
                    Level = data.Level.ToString(),
                    Year = data.Year.ToString(),
                    CveDetail = data.Detail,
                    Publish_date = data.Publish_Date.ToString(),
                    Update_date = data.Update_Date.ToString(),
                    UserName = "samsung",
                    Url = findCveDict[cve].FirstOrDefault().Url,
                    FileName = findCveDict[cve].FirstOrDefault().Path,
                    FuncName = findCveDict[cve].FirstOrDefault().FuncName,
                });
                Console.WriteLine("추가 완료");
            }
        }
    }

}
