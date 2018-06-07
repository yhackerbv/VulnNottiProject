using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VulnCrawler
{

    // 추상 클래스
    public abstract class VulnAbstractCrawler
    {
        public class Block
        {
            public int Num { get; set; }
            public bool HasCritical { get; set; }
            public string Code { get; set; }
            public string Hash { get; set; }
            public string AbsCode { get; set; }
            public IEnumerable<string> CriticalList { get; set; }

        }

        public class UserBlock
        {
            public int Len { get; set; }
            public string FuncName { get; set; }
            public string Hash { get; set; }
            public string Path { get; set; }

            public override bool Equals(object obj)
            {
                var block = obj as UserBlock;
                return block != null &&
                       Hash == block.Hash;
            }

            public override int GetHashCode()
            {
                var hashCode = -481433985;
                hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Hash);
                return hashCode;
            }
        }
        protected Regex extractMethodLine;
        protected HashSet<string> ReservedList { get; }
        protected abstract string ReservedFileName { get; }
        // = { "if", "return", "break", "while", "typedef" };
        /// <summary>
        /// 생성자
        /// 경로를 입력받아서(path)
        /// 레파지토리를 초기화하고
        /// 커밋 목록을 검색함
        /// </summary>
        /// <param name="path"></param>
        public VulnAbstractCrawler()
        {
            extractMethodLine = new Regex(RegexFuncPattern);
            ReservedList = new HashSet<string>();
            LoadReservedList();
        }
        // 소멸자
        ~VulnAbstractCrawler() {
            try
            {
                Repository?.Dispose();
            }
            catch { }
        }

        private void LoadReservedList()
        {
            try
            {
                var lines = File.ReadLines(ReservedFileName, Encoding.Default);
                foreach (var item in lines)
                { 
                    if (string.IsNullOrWhiteSpace(item))
                    {
                        continue;
                    }
                    ReservedList.Add(item);  
                }
            }
            catch(FileNotFoundException)
            {
                Console.WriteLine($"{this.GetType().ToString()} 예약어 파일 목록이 없습니다. 파일 이름 : {ReservedFileName}");
            }
        }
        protected virtual Regex MethodExtractor => new Regex(RegexFuncPattern);
        #region 메서드 패턴 정규식 그룹
        // 정규식 그룹화
        // @@ -oldStart,oldLines +newStart,newLines @@ MethodName():
        public static string OldStart => "oldStart";
        public static string OldLines => "oldLines";
        public static string NewStart => "newStart";
        public static string NewLines => "newLines";
        public static string MethodName => "methodName";
        #endregion

        public void Init(string path) {
            Console.WriteLine("로딩중");
            Console.WriteLine(path);
            Repository = new Repository(path);
           
            Console.WriteLine("로딩 완료");
            Commits = SearchCommits();
            Console.WriteLine($"Commits Count: {Commits.Count()}");
        }
        /// <summary>
        /// 레파지토리
        /// </summary>
        public Repository Repository { get; private set; }

        /// <summary>
        /// 커밋 목록
        /// </summary>
        public IEnumerable<Commit> Commits { get; private set; }
        /// <summary>
        /// 커밋에서 검색할 정규식 문자열
        /// </summary>
        public string SearchCommitPattern => @"CVE[ -]\d{4}[ -]\d{4}";
        /// <summary>
        /// 패치 코드에서 함수 찾을 정규식 패턴 문자열
        /// </summary>
        protected abstract string RegexFuncPattern { get; }
        protected abstract string Extension { get; }
        public virtual IEnumerable<PatchEntryChanges> GetPatchEntryChanges(Patch patch) {
            return patch.Where(e => e.Path.EndsWith(Extension)).ToList();
        }
        /// <summary>
        /// 정규식을 이용하여 @@ -\d,\d +\d,\d @@ MethodName(): 이런 패턴을 찾고
        /// 그룹화 하여 반환함 (OldStart, OldLines, NewStart, NewLines, MethodName
        /// </summary>
        /// <param name="patchCode">찾을 코드</param>
        /// <returns>정규식 그룹 컬렉션</returns>
        public abstract MatchCollection GetMatches(string patchCode);
        /// <summary>
        /// 파일스트림으로 부터 원본 함수 구하는 함수
        /// </summary>
        /// <param name="oldStream">파일 스트림</param>
        /// <param name="methodName">찾을 메서드 이름</param>
        /// <returns>함수 문자열</returns>
        protected abstract string GetOriginalFunc(Stream oldStream, string methodName);

        public abstract IDictionary<int, IEnumerable<UserBlock>> CrawlUserCode(StreamReader reader);

        protected abstract IList<Block> GetCriticalBlocks(string srcCode, IEnumerable<string> criticalList);
        /// <summary>
        /// 성능 개선을 위한
        /// 코드 라인 위치 기반 취약 원본 함수 추출 테스트용 함수 곧 삭제 예정
        /// </summary>
        public string GetOriginalFuncTest(Stream oldStream, string methodName, int start)
        {
            StringBuilder oldBuilder = new StringBuilder();
            
            using (var reader = new StreamReader(oldStream))
            {
                bool found = false;
                bool found2 = false;
                bool commentLine = false;
                int bracketCount = -1;
                string stringPattern = @"[""].*[""]";
                string commentPattern = @"\/\*.+\*\/";
                string commentPattern2 = @"\/\*";
                string commentPattern3 = @"\*\/";
                int readCount = 0;
                Queue<string> tempQ = new Queue<string>();
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    if (readCount++ < start)
                    {
                        tempQ.Enqueue(line);
                        continue;
                    }
                    Stack<string> tempStack = new Stack<string>();
                    while (tempQ.Count > 0)
                    {
                        string s = tempQ.Dequeue();
                        tempStack.Push(s);
                        string method = Regex.Escape(methodName);
                        if (Regex.Match(s, $"{method}").Success)
                        {
                            break;
                        }
                    }
                    while (tempStack.Count > 0)
                    {
                        string s = tempStack.Pop();
                        string trim = s.Trim();
                        if (commentLine)
                        {
                            if (Regex.IsMatch(trim, commentPattern3))
                            {
                                commentLine = false;
                                trim = Regex.Split(trim, commentPattern3)[1];
                            }
                            continue;
                        }
                        string removeString = Regex.Replace(trim, stringPattern, "");
                        // /* ~ 패턴
                        if (Regex.IsMatch(trim, commentPattern2))
                        {
                            // /* ~ */ 패턴이 아닌 경우
                            if (!Regex.IsMatch(trim, commentPattern))
                            {
                                commentLine = true;
                            }
                            trim = Regex.Split(trim, "/*")[0];
                        }
                        if (string.IsNullOrWhiteSpace(trim))
                        {
                            continue;
                        }
                        int openBracketCount = removeString.Count(c => c == '{');
                        int closeBracketCount = removeString.Count(c => c == '}');
                        int subtract = openBracketCount - closeBracketCount;
                        bracketCount += subtract;
                        // 메서드 시작 괄호 찾은 경우
                        if (found2)
                        {
                            // 괄호가 모두 닫혔으니 종료
                            if (bracketCount < 0)
                            {
                               // Console.WriteLine("괄호끝");
                                break;
                            }
                          //  oldBuilder.AppendLine(line);
                        }
                        else
                        {
                            if (openBracketCount > 0)
                            {
                                found2 = true;
                            }

                        }
                        oldBuilder.AppendLine(s);
                    }
                }
            }
            Console.WriteLine("찾음");
            Console.WriteLine(oldBuilder.ToString());
            Console.ReadLine();

            return oldBuilder.ToString();
        }
        public abstract IDictionary<string, IEnumerable<string>> ExtractGitCriticalMethodTable(string srcCode);

        public abstract string Abstract(string blockCode, IDictionary<string, string> dict, IDictionary<string, string> methodDict);
        /// <summary>
        /// 패치 전 코드 파일과 크리티컬 메서드 테이블로 부터 크리티컬 블록 추출
        /// </summary>
        /// <param name="oldBlob">패치 전 파일 Blob</param>
        /// <param name="table">크리티컬 메서드 테이블(Key: 메서드 이름, Value: 변수 리스트)</param>
        /// <returns></returns>
        public virtual IEnumerable<(string methodName, string oriFunc, IList<Block> blocks)> Process(Blob oldBlob, IDictionary<string, IEnumerable<string>> table) {
            foreach (var item in table)
            {
                var methodTable = new Dictionary<string, string>();
                var varTable = new Dictionary<string, string>();
                // 메서드 이름
                string methodName = item.Key;
                // 패치 전 원본 파일 스트림
                Stream oldStream = oldBlob.GetContentStream();
                // 패치 전 원본 함수 구하고
                string func = GetOriginalFunc(oldStream, methodName);
                
                string bs = string.Empty;
                string md5 = string.Empty;
                if (item.Value.Count() != 0)
                {
                    //Console.WriteLine("크리티컬 변수 목록");
                    //Console.ForegroundColor = ConsoleColor.Cyan;
                    //foreach (var c in item.Value)
                    //{
                    //    Console.WriteLine(c);
                    //}
                    //Console.ResetColor();
                    //Console.WriteLine("-------------------");
                    // 크리티컬 블록 추출
                    var blocks = new List<Block>();
                    //var blocks = GetCriticalBlocks(func, item.Value).ToList();
                    //if (blocks == null)
                    //{
                    //    continue;
                    //}
                    //foreach (var block in blocks)
                    //{
                        
                    //    block.CriticalList = item.Value;
                    //    /* 추상화 및 정규화 */
                    //    block.AbsCode = Abstract(block.Code, varTable, methodTable);
                    //    block.Hash = MD5HashFunc(block.AbsCode);

                    //}
                    /* 추상화 변환 테이블 출력 */
                    //foreach (var var in varTable)
                    //{
                    //    Console.WriteLine($"{var.Key}, {var.Value}");
                    //}

                    yield return (methodName, func, blocks);
                }
                
            }
        }
        /// <summary>
        /// 주석 제거 함수
        /// </summary>
        /// <param name="original">제거할 문자열</param>
        /// <returns>결과 문자열</returns>
        public abstract string RemoveComment(string original);

        /// <summary>
        /// 커밋 검색 함수(정규식 사용)
        /// 정규식은 SearchKeyword 사용함
        /// </summary>
        /// <returns>커밋 목록</returns>
        public virtual IEnumerable<Commit> SearchCommits() {
            // where => 조건에 맞는 것을 찾음(CVE-20\d\d-\d{4}로 시작하는 커밋만 골라냄)
            Console.WriteLine(Repository.Commits.Count());
            var commits = Repository.Commits
                                    .Where(c => Regex.Match(c.Message, SearchCommitPattern, RegexOptions.IgnoreCase).Success)
                                    .ToList();

            return commits;
        }

        /// <summary>
        /// 커밋 메시지로부터 CVE 코드 추출
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public string GetCVE(string msg) {
            var match = Regex.Match(msg, SearchCommitPattern, RegexOptions.IgnoreCase);

            if (match.Success) {
                return match.Value;
            }
            return string.Empty;
        }
        

        public MethodVarList ExtractMethodVariantList(string line, bool skipDefine=true)
        {
            line = line.Trim();
            if (string.IsNullOrWhiteSpace(line))
            {
                return null;
            }
            if (line.StartsWith("//"))
            {
                return null;
            }
            var methodVarList = new MethodVarList() { Methods = new List<string>(), Vars = new List<string>() };
            string declarePattern = @"(?<Declare>[a-zA-Z0-9_\.]+)\s+[a-zA-Z0-9_\.]+\s*(=|;|,)";
            // 메서드 정규식 패턴
            string methodPattern = @"([a-zA-Z0-9_\.]+)\s*\(";
            // 변수 정규식 패턴
            string fieldPattern = @"\*?(?<Field>([a-zA-Z0-9_\.]|\-\>)+)";
            string fieldArrayPattern = @"(?<ArrayName>[a-zA-Z0-9_\.]+)\[.+\]";
            string invalidPattern = @"^[\d\.]+";

            string commentPattern = @"[""].*[""]";

            string commentPattern2 = @"\/\/.*";
            string commentPattern3 = @"\/\*.+\*\/";

            line = Regex.Replace(line, commentPattern, "");
            line = Regex.Replace(line, commentPattern2, "");
            line = Regex.Replace(line, commentPattern3, "");
            // 메서드 목록
            var methodSets = new HashSet<string>();

            // 선언 타입명 추출
            var declareMatch = Regex.Match(line, Regex.Escape(declarePattern));
            string declareName = string.Empty;
            if (declareMatch.Success)
            {
                declareName = declareMatch.Groups["Declare"]?.Value ?? string.Empty;

            }
            var methods = Regex.Matches(line, methodPattern);
            // 현재 코드 라인에서 메서드 목록 추가
            foreach (var met in methods)
            {
                var method = met as Match;
                if (method.Success)
                {
                    if (ReservedList.Contains(method.Groups[1].Value))
                    {
                        continue;
                    }
                    methodSets.Add(method.Groups[1].Value);
                }
            }
            //  Console.WriteLine("----");
            var arrayNames = Regex.Matches(line, fieldArrayPattern)
                            .Cast<Match>()
                            .Where(m => {
                                if (m.Value.Equals(declareName))
                                {
                                    return false;
                                }

                                /* 제일 앞자리가 숫자로 시작하면 넘어감 */
                                if (Regex.IsMatch(m.Value, invalidPattern))
                                {
                                    return false;
                                }

                                /* 전 단계에서 구한 메서드 목록에 있으면 넘어감 */
                                if (methodSets.Contains(m.Value))
                                {
                                    return false;
                                }
                                /* 예약어 목록에 있으면 넘어감 */
                                if (ReservedList.Contains(m.Value))
                                {
                                    return false;
                                }

                                /* 알파벳이 하나도 없으면 넘어감 */
                                if (!m.Value.Any(c => char.IsLetter(c)))
                                {
                                    return false;
                                }

                                ///* 대문자로 구성된 변수면 넘어감 */
                                //if (skipDefine && m.Value.All(c => char.IsUpper(c) || !char.IsLetter(c)))
                                //{
                                //    return false;
                                //}

                                return true;
                            })
                            .Distinct(new MatchComparer());

            var arrays = arrayNames.Select(m => m.Groups["ArrayName"].Value);

            var vars = Regex.Matches(line, fieldPattern)
                            .Cast<Match>()
                            .Where(m => {
                                if (m.Value.Equals(declareName))
                                {
                                    return false;
                                }

                                /* 제일 앞자리가 숫자로 시작하면 넘어감 */
                                if (Regex.IsMatch(m.Value, invalidPattern))
                                {
                                    return false;
                                }
                                
                                /* 전 단계에서 구한 메서드 목록에 있으면 넘어감 */
                                if (methodSets.Contains(m.Value))
                                {
                                    return false;
                                }
                                /* 예약어 목록에 있으면 넘어감 */
                                if (ReservedList.Contains(m.Value))
                                {
                                    return false;
                                }
                                if (m.Value.StartsWith("-"))
                                {
                                    return false;
                                }
                                /* 알파벳이 하나도 없으면 넘어감 */
                                if(!m.Value.Any(c => char.IsLetter(c)))
                                {
                                    return false;
                                }

                                ///* 대문자로 구성된 변수면 넘어감 */
                                //if (skipDefine && m.Value.All(c => char.IsUpper(c) || !char.IsLetter(c)))
                                //{
                                //    return false;
                                //}

                                return true;
                            })
                            .Distinct(new MatchComparer());

     
            foreach (var x in vars)
            {
                if (x.Success)
                {
                    var field = x.Groups["Field"].Value;

                    /* a->b 포인터 변수 나눠서 추가 */
                    if (field.Contains("->"))
                    {
                        var connects = Regex.Split(field, "->");
                        var connectList = new List<string>();

                        string s = string.Empty;
                        foreach (var c in connects)
                        {
                            if (s == string.Empty)
                            {
                                s = c;
                            }
                            else
                            {
                                s = string.Join("->", s, c);
                            }
                            connectList.Add(s);
                        }
                        foreach (var c in connectList)
                        {
                            if (c == connects[connects.Length-1])
                            {
                                continue;
                            }
                            if (methodVarList.Vars.Contains(c))
                            {
                                continue;
                            }
                            methodVarList.Vars.Add(c);
                        }
                        continue;
                    }
                    methodVarList.Vars.Add(field);
                }
            }
            foreach (var x in arrays)
            {
                 methodVarList.Vars.Add(x);
            }
            foreach (var m in methodSets)
            {
                methodVarList.Methods.Add(m);
            }
            return methodVarList;
        }

        /// <summary>
        /// 크리티컬 변수 목록 추출
        /// </summary>
        /// <param name="line">현재 코드줄</param>
        /// <returns></returns>
        public IEnumerable<string> ExtractCriticalVariant(string line, bool skipDefine=true)
        {
            line = line.Trim();
            if (string.IsNullOrWhiteSpace(line))
            {
                yield break;
            }
            if (line.StartsWith("//"))
            {
                yield break;
            }
            string declarePattern = @"(?<Declare>[a-zA-Z0-9_\.]+) [a-zA-Z0-9_\.]+ =";
            // 메서드 정규식 패턴
            string methodPattern = @"([a-zA-Z0-9_\.]+)\s*\(";
            // 변수 정규식 패턴
            string fieldPattern = @"\*?(?<Field>([a-zA-Z0-9_\.]|\-\>)+)";
            string invalidPattern = @"^[\d\.]+";

            string commentPattern = @"[""].*[""]";

            string commentPattern2 = @"\/\/.*";
            string commentPattern3 = @"\/\*.+\*\/";

            line = Regex.Replace(line, commentPattern, "");
            line = Regex.Replace(line, commentPattern2, "");
            line = Regex.Replace(line, commentPattern3, "");
            // 메서드 목록
            var methodSets = new HashSet<string>();

            // 선언 타입명 추출
            var declareMatch = Regex.Match(line, declarePattern);
            string declareName = string.Empty;
            if (declareMatch.Success)
            {
                declareName = declareMatch.Groups["Declare"]?.Value ?? string.Empty;

            }
            //Console.WriteLine($"선언 : {declareName}");


            var methods = Regex.Matches(line, methodPattern);
            // 현재 코드 라인에서 메서드 목록 추가
            foreach (var met in methods)
            {
                var method = met as Match;
                if (method.Success)
                {
                  //  Console.WriteLine(method.Groups[1].Value);
                    methodSets.Add(method.Groups[1].Value); // aaaa
                }
            }
          //  Console.WriteLine("----");
            var vars = Regex.Matches(line, fieldPattern)
                            .Cast<Match>()
                            .Where(m => {
                                if (m.Value.Equals(declareName))
                                {
                                    return false;
                                }
                                /* 제일 앞자리가 숫자로 시작하면 넘어감 */
                                if (Regex.IsMatch(m.Value, invalidPattern))
                                {
                                    return false;
                                }
                                /* 전 단계에서 구한 메서드 목록에 있으면 넘어감 */
                                if (methodSets.Contains(m.Value))
                                {
                                    return false;
                                }
                                /* 예약어 목록에 있으면 넘어감 */
                                if (ReservedList.Contains(m.Value))
                                {
                                    return false;
                                }
                                /* 알파벳이 하나도 없으면 넘어감 */
                                if(!m.Value.Any(c => char.IsLetter(c)))
                                {
                                    return false;
                                }
                                /* 대문자로 구성된 변수면 넘어감 */
                                if (skipDefine && m.Value.All(c => char.IsUpper(c) || !char.IsLetter(c)))
                                {
                                    return false;
                                }
                                return true;
                            })
                            .Distinct(new MatchComparer());

            foreach (var x in vars)
            {
                var field = x as Match;
                if (field.Success)
                {
                    yield return field.Value;
                }
            }
        }

        /// <summary>
        /// MD5 함수
        /// </summary>
        /// <param name="str">INPUT 문자열</param>
        /// <returns>결과 문자열</returns>
        public static string MD5HashFunc(string str) {
            StringBuilder MD5Str = new StringBuilder();
            byte[] byteArr = Encoding.ASCII.GetBytes(str);
            byte[] resultArr = (new MD5CryptoServiceProvider()).ComputeHash(byteArr);
            for (int cnti = 0; cnti < resultArr.Length; cnti++) {
                MD5Str.Append(resultArr[cnti].ToString("X2"));
            }
            return MD5Str.ToString();
        }

    }

    class MatchComparer : IEqualityComparer<Match>
    {
        public bool Equals(Match x, Match y)
        {
            return x.Value.Equals(y.Value);
        }

        public int GetHashCode(Match obj)
        {
            return obj.Value.GetHashCode();
        }
    }

    public class MethodVarList
    {
        public IList<string> Vars { get; set; }
        public IList<string> Methods { get; set; }
    }
}
