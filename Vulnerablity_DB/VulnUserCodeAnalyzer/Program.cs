
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
            /* 연도별 CVE JSON 파일 로드 */
            CVE_JSON.AutoLoad();

            /* 크롤러 타입 */
            var crawler = new VulnC();

            /* 매칭을 위한 자료구조 Bloom Filter */
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

            /* hashDict = 사용된 사용자 함수 정보 */
            var hashDict = new Dictionary<int, HashSet<VulnAbstractCrawler.UserBlock>>();
            /* 경과 시간 체크 */
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            DirectoryInfo dirInfo = new DirectoryInfo(@"C:\code");

            /* 모든 .c 파일 탐색 */
            var codeFiles = dirInfo.EnumerateFiles("*.c", SearchOption.AllDirectories);
            int totalFileCount = codeFiles.Count();
            int count = 0;
            foreach (var codeFile in codeFiles)
            {
                Console.WriteLine(codeFile.FullName);
                using (var reader = codeFile.OpenText())
                {
                    /* 사용자 코드를 함수별로 나눔 */
                    var dict = crawler.CrawlUserCode(reader);
                    foreach (var item in dict)
                    {
                        /* hashDict의 키와 item.key는 함수 블록의 코드 길이 */
                        if (!hashDict.ContainsKey(item.Key))
                        {
                            hashDict[item.Key] = new HashSet<VulnAbstractCrawler.UserBlock>();
                        }
                        /* item.Value는 각 코드 길이 마다의 블록 정보 
                         * Bloom Filter에 코드 블록 해쉬값 기록
                         */
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
            var findBlocks = new Queue<VulnAbstractCrawler.UserBlock>();
            var vulnDict = new Dictionary<string, IEnumerable<VulnRDS._Vuln>>();
            foreach (var set in hashDict)
            {
                /* 사용자 코드의 길이 마다 DB로 부터 같은 길이의 CVE 레코드 목록 가져옴 */
                var cveList = VulnRDS.SelectVulnbyLen(set.Key).Select(v => v.Cve).Distinct();
                foreach (var cve in cveList)
                {
                    if (!vulnDict.ContainsKey(cve))
                    {
                        vulnDict[cve] = new HashSet<VulnRDS._Vuln>();
                        var vulnHashSet = vulnDict[cve] as HashSet<VulnRDS._Vuln>;
                        /* 같은 길이의 CVE에서 또 같은 종류의 CVE 레코드 목록 가져옴
                         * 같은 종류의 CVE 레코드들이 사용자 코드에서 모두 포함되어야 
                         * CVE를 가지고 있다고 인정하는 프로그램 정책 때문 
                         */
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
            /* 본격적인 취약점 매칭 부분 */
            foreach (var vulnSet in vulnDict)
            {
                //Console.WriteLine($"-----cve:{vulnSet.Key}");
                bool match = false;
                foreach (var vuln in vulnSet.Value)
                {
                    /* 사용자 코드 해쉬 저장해논 bloom filter에 취약점 레코드 해쉬값들이 포함되는지 확인
                     * 포함이 된다는 건 해당 취약점 레코드가 사용자 코드에도 있다는 뜻(취약점)
                     * 같은 종류의 CVE 레코드가 전부 필터에 포함된다면 취약점으로 판단한다.
                     */
                    if (filter.Contains(vuln.BlockHash))
                    {
                        if (hashDict.ContainsKey(vuln.LenFunc))
                        {
                            /* Bloom Filter는 아쉽게도 포함 여부만 알 수 있기에 
                             * 포함되었음을 알았다면 검색해서 정보를 구한다. */
                            var userBlock = hashDict[vuln.LenFunc].FirstOrDefault(b => b.Hash == vuln.BlockHash);
                            if (userBlock == null)
                            {
                                continue;
                            }
                            /* 해당 유저 블록을 임시 저장한다.
                             * 밑에서 블록 정보를 DB로 전송하기 위해서다. 
                             */
                            if (!findCveDict.ContainsKey(vuln.Cve))
                            {
                                findCveDict[vuln.Cve] = new List<VulnAbstractCrawler.UserBlock>();
                            }
                            userBlock.Url = vuln.Url;
                            findCveDict[vuln.Cve].Add(userBlock);
                            match = true;
                        }
                    }
                    else
                    {
                        match = false;
                        break;
                    }
                }
                /* 취약점 레코드가 전부 있어야 CVE 찾음 인정 */
                if (match)
                {
                    Console.WriteLine($"CVE 찾음 {vulnSet.Key}");
                    /* 찾았으면 cve값을 기록함 밑에서 찾은 cve 정보 전송하기 위해 */
                    findCveList.Add(vulnSet.Key);
                }
                else
                {
                    Console.WriteLine("없음");
                }
            }
            stopwatch.Stop();
            /* 매칭 끝 후처리 (출력, DB 전송 등) */
            var hours = stopwatch.Elapsed.Hours;
            var minutes = stopwatch.Elapsed.Minutes;
            var seconds = stopwatch.Elapsed.Seconds;
            Console.WriteLine($"경과 시간 {hours.ToString("00")}:{minutes.ToString("00")}:{seconds.ToString("00")}");
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

                /* 취약점 타입 분류 */
                string type = "NORMAL";
                if (data.Detail.IndexOf("overflow", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "OVERFLOW";
                }
                else if (data.Detail.IndexOf("xss", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "XSS";
                }
                else if (data.Detail.IndexOf("injection", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "SQLINJECTION";
                }
                else if (data.Detail.IndexOf("dos", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "DOS";
                }
                else if (data.Detail.IndexOf("Memory", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "MEMORY";
                }
                else if (data.Detail.IndexOf("CSRF", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "CSRF";
                }
                else if (data.Detail.IndexOf("inclusion", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "FILEINCLUSION";
                }
                else if (data.Detail.IndexOf("EXCUTE", StringComparison.CurrentCultureIgnoreCase) > 0)
                {
                    type = "EXCUTE";
                }
                var urlBytes = Convert.FromBase64String(findCveDict[cve].FirstOrDefault().Url);
                string url = Encoding.Unicode.GetString(urlBytes);

                /* DB 전송 */
                VulnRDS.InsertVulnDetail(new VulnRDS.Vuln_detail
                {
                    CveName = data.Code,
                    Type = type,
                    Level = data.Level.ToString(),
                    Year = data.Year.ToString(),
                    CveDetail = data.Detail,
                    Publish_date = data.Publish_Date.ToString("yyyy-MM-dd"),
                    Update_date = data.Update_Date.ToString("yyyy-MM-dd"),
                    UserName = "samsung",
                    Url = url,
                    FileName = findCveDict[cve].FirstOrDefault().Path.Replace(@"C:\code", ""),
                    FuncName = findCveDict[cve].FirstOrDefault().FuncName,
                    Product = data.Type,
                });
                Console.WriteLine("추가 완료");
            }
        }
    }

}
