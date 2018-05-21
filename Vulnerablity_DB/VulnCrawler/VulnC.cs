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

        protected override IList<Block> GetCriticalBlocks(string srcCode, IEnumerable<string> criticalList)
        {
           // srcCode = Regex.Replace(srcCode, @"if.+\n\{", @"if.+\{", RegexOptions.Multiline);

            var split = srcCode.Split('\n');
            int bracketCount = 0;
            var blockList = new List<Block>();
            StringBuilder builder = new StringBuilder();
            var crList = criticalList as HashSet<string>;
            if (crList == null)
            {
                return null;
            }
            bool mainLine = true; /* 현재 라인이 메인 코드 라인인지 */
           
            int blockNum = 1; /* 블록 번호 */
            

            bool group = false;
            Queue<string> groupQ = new Queue<string>();
            var mainQ = new Queue<string>();
            
            foreach (var line in split)
            {
                bool criticalBlock = false; /* 현재 라인이 크리티컬 블록 라인인지 */

                string trim = line.Trim();

                if (Regex.IsMatch(trim, @"^(if|for|while)"))
                {
                    group = true;
                    mainLine = false;
                    groupQ.Enqueue(line);
                    if (trim.EndsWith("{"))
                    {
                        group = true;
                    }
                    else if (trim.EndsWith("}"))
                    {
                        group = false;
                    }
                    else if(trim.EndsWith(";"))
                    {
                        group = false;
                    }
                    continue;
                }

                if (group)
                {
                    groupQ.Enqueue(line);
                    if (trim.EndsWith("}"))
                    {
                        group = false;
                    }
                    else if (trim.EndsWith(";"))
                    {
                        group = false;
                    }
                    continue;
                }

                mainQ.Enqueue(line);

                StringBuilder mainBuilder = new StringBuilder();
                if (!mainLine)
                {
                    while(mainQ.Count > 0)
                    {
                        string s = mainQ.Dequeue();
                        if (!criticalBlock)
                        {
                            foreach (var var in ExtractCriticalVariant(s))
                            {
                                if (crList.Contains(var))
                                {
                                    criticalBlock = true;
                                    break;
                                }
                            }
                        }
                        mainBuilder.AppendLine(s);
                    }
                    if (mainBuilder.Length > 0)
                    {
                        blockList.Add(new Block { Code = mainBuilder.ToString(), HasCritical = criticalBlock, Num = blockNum++ });
                        //continue;
                    }
                }

                StringBuilder groupBuilder = new StringBuilder();
                while (groupQ.Count > 0)
                {
                    var s = groupQ.Dequeue();
                    if (!criticalBlock)
                    {
                        foreach (var var in ExtractCriticalVariant(s))
                        {
                            if (crList.Contains(var))
                            {
                                criticalBlock = true;
                                break;
                            }
                        }
                    }
                    groupBuilder.AppendLine(s);
                }
                if (groupBuilder.Length > 0)
                {
                    blockList.Add(new Block { Code = groupBuilder.ToString(), HasCritical = criticalBlock, Num = blockNum++ });
                    continue;
                }




                mainLine = true;




            }

            Console.WriteLine("끝");
            return blockList;
        }
    }
}
