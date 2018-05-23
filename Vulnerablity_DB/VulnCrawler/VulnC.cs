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
            
            var blockList = new List<Block>();
            StringBuilder builder = new StringBuilder();
            var crList = criticalList as HashSet<string>;
            if (crList == null)
            {
                return null;
            }
            var split = srcCode.Split('\n');
            var mainQ = new Queue<string>();
            var groupQ = new Queue<string>();
            bool mainLine = true;
            int crNum = 1;
            int bracketCount = 1;
            bool prevStartBlock = false;
            int totalSoBracketCount = 0;
            foreach (var line in split)
            {

                bool criticalBlock = false;
                string trimLine = line.Trim();
                if (string.IsNullOrWhiteSpace(trimLine))
                {
                    continue;
                }
                if (mainLine)
                {
                    bracketCount = 1;
                    if (trimLine.StartsWith("else"))
                    {
                        groupQ.Enqueue(line);
                        mainLine = false;
                        continue;
                    }

                    StringBuilder groupBuilder = new StringBuilder();
                    while(groupQ.Count > 0)
                    {
                        string s = groupQ.Dequeue();
                        if (!criticalBlock)
                        {
                            foreach (var item in ExtractCriticalVariant(s))
                            {
                                if (crList.Contains(item))
                                {
                                    criticalBlock = true;
                                    break;
                                }
                            }
                        }
                        groupBuilder.AppendLine(s);
                    }
                    if (!string.IsNullOrWhiteSpace(groupBuilder.ToString()))
                    {
                        blockList.Add(new Block { Code = groupBuilder.ToString(), HasCritical = criticalBlock, Num = crNum++});
                    }

                    if (Regex.IsMatch(trimLine, @"^(if|for|while|switch|do)\s*"))
                    {
                        /* syntax를 만났을 때 끝에 {가 없으면 */
                        if (!trimLine.EndsWith("{"))
                        {
                            int soBracketOpenCount = trimLine.Count(c => c == '(');
                            int soBracketCloseCount = trimLine.Count(c => c == ')');
                            totalSoBracketCount = (soBracketOpenCount - soBracketCloseCount);
                            /* if(s()
                             *  && b) 
                             * 이렇게 소괄호가 안맞고 밑 라인에서 이어서 작성하는 경우
                             */
                            mainLine = false;
                            prevStartBlock = true;
                            
                        }
                        else if (trimLine.EndsWith(";"))
                        {
                            mainLine = true;
                        }
                        else
                        {
                            mainLine = false;
                            bracketCount++;
                        }
                        
                        groupQ.Enqueue(line);
                        

                        continue;
                    }


                    mainQ.Enqueue(line);
                }
                else
                {
                    /* 소괄호 수 세기 */
                    int soBracketOpenCount = trimLine.Count(c => c == '(');
                    int soBracketCloseCount = trimLine.Count(c => c == ')');
                    /* 중괄호 수 세기 */
                    int openBracketCount = trimLine.Count(c => c == '{');
                    int closeBracketCount = trimLine.Count(c => c == '}');
                    int subtract = openBracketCount - closeBracketCount;
                    bracketCount += subtract;
                    groupQ.Enqueue(line);
                    if (prevStartBlock)
                    {
                        totalSoBracketCount += (soBracketOpenCount - soBracketCloseCount);
                        prevStartBlock = false;
                        if(totalSoBracketCount > 0)
                        {
                            prevStartBlock = true;
                            continue;
                        }
                        else if (Regex.IsMatch(trimLine, @"^(if|for|while|switch|do)\s*"))
                        {
                            prevStartBlock = true;
                            continue;

                        }
                        else if(trimLine.EndsWith(";"))
                        {
                            bracketCount--;
                        }
                    }

                    if (bracketCount <= 1)
                    {
                        if (soBracketOpenCount > soBracketCloseCount)
                        {
                            continue;
                        }
                        if (!(trimLine.EndsWith("}") || trimLine.EndsWith(";")))
                        {
                            continue;
                        }
                        if (trimLine.Contains("else"))
                        {
                            bracketCount++;
                            prevStartBlock = true;
                            continue;
                        }
                        mainLine = true;
                    }

                    /* 메인 라인 블록 추가 */
                    StringBuilder mainBuilder = new StringBuilder();
                    while (mainQ.Count > 0)
                    {
                        string s = mainQ.Dequeue();
                        if (!criticalBlock)
                        {
                            /* 크리티칼 블록 선정 */
                            foreach (var item in ExtractCriticalVariant(s))
                            {
                                if (crList.Contains(item))
                                {
                                    criticalBlock = true;
                                    break;
                                }
                            }
                        }
                        mainBuilder.AppendLine(s);
                    }
                    string mains = mainBuilder.ToString();
                    if (!string.IsNullOrWhiteSpace(mains))
                    {
                        blockList.Add(new Block { Code = mains, HasCritical = criticalBlock, Num = crNum++ });
                    }
                }
            }

            bool cb = false;
            if (mainQ.Count > 0)
            {
                StringBuilder mainBuilder = new StringBuilder();
                while (mainQ.Count > 0)
                {
                    string s = mainQ.Dequeue();
                    if (!cb)
                    {
                        foreach (var item in ExtractCriticalVariant(s))
                        {
                            if (crList.Contains(item))
                            {
                                cb = true;
                                break;
                            }
                        }
                    }
                    mainBuilder.AppendLine(s);
                }

                if (mainBuilder.Length > 0)
                {
                    blockList.Add(new Block { Code = mainBuilder.ToString(), HasCritical = cb, Num = crNum++ });
                }
            }
            else
            {
                StringBuilder groupBuilder = new StringBuilder();
                while (groupQ.Count > 0)
                {
                    string s = groupQ.Dequeue();
                    if (!cb)
                    {
                        foreach (var item in ExtractCriticalVariant(s))
                        {
                            if (crList.Contains(item))
                            {
                                cb = true;
                                break;
                            }
                        }
                    }
                    groupBuilder.AppendLine(s);
                }

                if (groupBuilder.Length > 0)
                {
                    blockList.Add(new Block { Code = groupBuilder.ToString(), HasCritical = cb, Num = crNum++ });
                }
            }

            return blockList;
        }

        public override string Abstract(string blockCode, IDictionary<string, string> dict, IDictionary<string, string> methodDict)
        {
            var split = blockCode.Split('\n');
            var varName = "VAL";
            var methodName = "FUNC";
            int varIdx = dict.Count();
            int methodIdx = methodDict.Count();

            var removes = Regex.Split(blockCode, Environment.NewLine, RegexOptions.Multiline);
            StringBuilder builder = new StringBuilder();
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            foreach (var item in removes)
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }
                Console.Write(item);
                builder.Append(item);
                // Console.ReadLine();
            }
//            Console.WriteLine(builder.ToString());
            Console.ResetColor();
            foreach (var line in split)
            {
                var varList = ExtractMethodVariantList(line, skipDefine: false);
                if (varList == null)
                {
                    continue;
                }
                foreach (var var in varList.Vars)
                {
                    if (!dict.ContainsKey(var))
                    {
                        dict[var] = varName + varIdx++;
                    }
                }

                foreach (var m in varList.Methods)
                {
                    if (!methodDict.ContainsKey(m))
                    {
                        methodDict[m] = methodName + methodIdx++;
                    }
                }

            }

            var sortVarDict = dict.OrderByDescending(p => p.Key).ToDictionary(p => p.Key, p => p.Value);
            var sortMethodDict = methodDict.OrderByDescending(p => p.Key).ToDictionary(p => p.Key, p => p.Value);

            string temp = blockCode;
            foreach (var pair in sortVarDict)
            {
                temp = Regex.Replace(temp, $@"\b{pair.Key}\b", pair.Value);
            }

            foreach (var pair in sortMethodDict)
            {
                temp = Regex.Replace(temp, $@"\b{pair.Key}\b", pair.Value);

            }
            temp = Regex.Replace(temp, @"\s", "", RegexOptions.Multiline);
            temp = Regex.Replace(temp, @"{|}|;|\)|\(", "");
            temp = temp.ToUpper();


            return temp;
        }
    }
}
