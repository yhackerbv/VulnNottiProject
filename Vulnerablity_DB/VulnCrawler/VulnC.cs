using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VulnCrawler
{
    public class VulnC : VulnAbstractCrawler
    {
//        protected override string RegexFuncPattern => $@"@@ \-(?<{OldStart}>\d+),(?<{OldLines}>\d+) \+(?<{NewStart}>\d+),(?<{NewLines}>\d+) @@ (?<{MethodName}>(static)?( const )? [\w]+ [\w]+\([\w \*\,\t\n]*[\)\,])";
        protected override string RegexFuncPattern => $@"(?<{MethodName}>(unsigned|static)?( const )? [\w]+ [\w]+\(([\w \*\,\t\n])*[\)\,])";
        protected override string Extension => ".c";
        protected override string ReservedFileName => "CReserved.txt";
        public override MatchCollection GetMatches(string patchCode) {
            var regs = Regex.Matches(patchCode, RegexFuncPattern);
            return regs;
        }
        public override string RemoveComment(string original) {
            string txt = Regex.Replace(original, Environment.NewLine, "");

            //StringBuilder sb = new StringBuilder();
            //sb.Append("\"\"\"");
            //sb.Append(@".*");
            //sb.Append("\"\"\"");
            string replace = txt;
            //if (Regex.Match(txt, sb.ToString()).Success) {
            //    replace = Regex.Replace(txt, sb.ToString(), "");
            //}
            return replace;
        }

        public override IDictionary<string, IEnumerable<string>> ExtractGitCriticalMethodTable(string srcCode)
        {
            var table = new Dictionary<string, IEnumerable<string>>();
            string prevMethodName = string.Empty;
            StringBuilder builder = new StringBuilder();
            // 라인으로 나누고 @@가 시작하는 곳까지 생략
            var split = Regex.Split(srcCode, "\n").SkipWhile(s => !s.StartsWith("@@")).ToArray();
            for(int i = 0; i < split.Length; i++)
            {
                string line = split[i].Trim();
                // 문자열 제거
                line = Regex.Replace(line, @""".+""", "");

                var methodMatch = extractMethodLine.Match(line);
                string methodName = methodMatch.Groups[MethodName].Value.Trim();
                // 추가된, 제거된 라인인지 확인
                if (Regex.IsMatch(line, @"^[+-]\s"))
                {
                    // 주석문인지 확인
                    if (Regex.IsMatch(line, @"^[+-]\s*(\*|\/\*|\*\/)"))
                    {
                        continue;
                    }
                    Console.WriteLine(line);
                    builder.AppendLine(line);
                    continue;
                }
                // 메서드 매칭이 성공했거나 마지막 문단일 경우
                if (methodMatch.Success || i == split.Length - 1)
                {
                    if (string.IsNullOrWhiteSpace(prevMethodName))
                    {
                        builder.Clear();
                        prevMethodName = methodName;
                        continue;
                    }
                    if (methodName.Contains("return"))
                    {
                        continue;
                    }
                    if (methodName.Contains("="))
                    {
                        continue;
                    }
                    if (!table.ContainsKey(prevMethodName))
                    {                 
                        table[prevMethodName] = new HashSet<string>();
                    }
                    var list = table[prevMethodName] as HashSet<string>;
                    foreach (var b in Regex.Split(builder.ToString(), "\n"))
                    {
                        // 각 수집된 라인 별로 크리티컬 변수 선정
                        foreach (var var in ExtractCriticalVariant(b))
                        {
                            if (string.IsNullOrWhiteSpace(var))
                            {
                                continue;
                            }
                            list.Add(var);
                        }
                    }
                    prevMethodName = methodName;
                    builder.Clear();
                }
            }
            return table;
        }
        protected override string GetOriginalFunc(Stream oldStream, string methodName) {
            StringBuilder oldBuilder = new StringBuilder();
            string method = Regex.Escape(methodName);
            using (var reader = new StreamReader(oldStream)) {
                bool found = false;
                bool found2 = false;
                bool commentLine = false;
                int bracketCount = -1;
                string stringPattern = @"[""].*[""]";
                string commentPattern = @"\/\*.+\*\/";
                string commentPattern2 = @"\/\*";
                string commentPattern3 = @"\*\/";
                while (!reader.EndOfStream) {
                    string line = reader.ReadLine();
                    // 메서드를 찾은 경우
                    if (found)
                    {
                        string trim = line.Trim();
                        // 범위 주석 진행되고 있으면 넘어감
                        if (commentLine)
                        {
                            // 혹시 범위 주석이 끝났는지 체크
                            if (Regex.IsMatch(trim, commentPattern3))
                            {
                                commentLine = false;
                                trim = Regex.Split(trim, commentPattern3)[1];
                            }
                            else
                            {
                                continue;
                            }
                        }
                        // "" 문자열 제거
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
                        // 비어있는 경우 넘어감
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
                            oldBuilder.AppendLine(line);
                            // 괄호가 모두 닫혔으니 종료
                            if (bracketCount < 0)
                            {
                                break;
                            }
                        }
                        else // 메서드는 찾았으나 아직 시작 괄호를 못찾은 경우
                        {
                            oldBuilder.AppendLine(line);
                            if (openBracketCount > 0)
                            {
                                found2 = true;
                            }
                            else
                            {
                                //아직 { 괄호를 못찾았는데 );를 만났다면 메서드 선언 부분이니 넘어감
                                if (trim.EndsWith(");"))
                                {
                                    found = false;
                                    oldBuilder.Clear();
                                    continue;
                                }
                            }
                        }
                    }
                    // 아직 메서드를 못찾은 경우
                    else
                    {
                        // 메서드 찾았는지 확인
                        if (Regex.Match(line, $"{method}").Success)
                        {
                            string trim = line.Trim();
                            // 주석으로 시작했다면 넘어감
                            if (trim.StartsWith("//"))
                            {
                                continue;
                            }

                            if (trim.StartsWith("/*"))
                            {
                                continue;
                            }
                            
                            // 혹시 메서드가 문자열 사이에 있다면 넘어감..
                            if (Regex.Match(trim, $@"""[.]*({method})").Success)
                            {
                                continue;
                            }
                            // 만약 찾은 메서드 라인에서 중괄호 {가 시작된 경우
                            if (Regex.Match(trim, $@"{method}\s*" + @"\{").Success)
                            {
                                // 동시에 } 닫히기까지 한 경우 드물겠지만..
                                if (trim.EndsWith("}"))
                                {
                                    oldBuilder.AppendLine(line);
                                    break;
                                }
                                found2 = true;
                            }
                            // 메서드 찾음
                            found = true;
                            oldBuilder.AppendLine(line);
                        }
                    }
                }
            }
            return oldBuilder.ToString();
        }

        protected override IList<string> GetCriticalBlocks(string srcCode, IEnumerable<string> criticalList)
        {
            var split = srcCode.Split('\n');
            int bracketCount = 0;
            var blockList = new List<string>();
            StringBuilder builder = new StringBuilder();
            var crList = criticalList as HashSet<string>;
            if (crList == null)
            {
                return null;
            }
            bool mainLine = true; /* 현재 라인이 메인 코드 라인인지 */
            foreach (var line in split)
            {
                string trim = line.Trim();
                /* 중괄호 수 세기 */
                int openBracketCount = trim.Count(c => c == '{');
                int closeBracketCount = trim.Count(c => c == '}');
                int subtract = openBracketCount - closeBracketCount;
                bracketCount += subtract;

                /* 중괄호 연산 결과 1이라는 것은 메인 라인 */
                if (bracketCount == 1)
                {
                    /* 
                     * 깊이가 1인데 mainLine이 
                     * false 이면 넘어왔다는 것이니 현재까지 코드
                     * blockList에 추가
                     */
                    if (!mainLine)
                    {
                        string s = builder.ToString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            blockList.Add(s);
                            builder.Clear();
                        }
                    }
                    mainLine = true;
                }
                /* 2 이상이라는 건 메인 라인 X */
                else if(bracketCount >= 2)
                {
                    /* 
                     * 깊이가 2 이상인데 mainLine이 
                     * true면 넘어왔다는 것이니 현재까지 코드
                     * blockList에 추가
                     */
                    if (mainLine)
                    {
                        string s = builder.ToString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            blockList.Add(s);
                            builder.Clear();
                        }
                    }
                    mainLine = false;
                }
                /* 이도 저도 아니면 그냥 넘어감 */
                else
                {
                    continue;
                }

                /* 현재 코드 라인에서 변수 추출시켜서 크리티컬 리스트와 대조 */
                foreach (var var in ExtractCriticalVariant(line))
                {
                    /* 크리티컬 리스트에 추출한 변수가 들어있다면 추가 */
                    if (criticalList.Contains(var))
                    {
                        builder.AppendLine(line);
                        break;
                    }
                }

            }
            return blockList;
        }
    }
}
