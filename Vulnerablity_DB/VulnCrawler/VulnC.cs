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
        protected override string RegexFuncPattern => $@"@@ \-(?<{OldStart}>\d+),(?<{OldLines}>\d+) \+(?<{NewStart}>\d+),(?<{NewLines}>\d+) @@ (?<{MethodName}>(static)?( const )? [\w]+ [\w]+\([\w \*\,\t\n]*[\)\,])";
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

        protected override string GetOriginalFunc(Stream oldStream, string methodName) {
            StringBuilder oldBuilder = new StringBuilder();
            methodName = Regex.Escape(methodName);
            using (var reader = new StreamReader(oldStream)) {
                Console.WriteLine(methodName);


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
                        if (Regex.Match(line, $"{methodName}").Success)
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
                            if (Regex.Match(trim, $@"""[.]*({methodName})").Success)
                            {
                                continue;
                            }

                            // 만약 찾은 메서드 라인에서 중괄호 {가 시작된 경우
                            if (Regex.Match(trim, $@"{methodName}\s*" + @"\{").Success)
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
            Console.WriteLine(oldBuilder.ToString());
            Console.ReadLine();

            return oldBuilder.ToString();
        }

        

    }
}
