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
                        Console.WriteLine("찾았었음");
                        string trim = line.Trim();

                        if (commentLine)
                        {
                            if (Regex.IsMatch(trim, commentPattern3))
                            {
                                commentLine = false;
                                trim = Regex.Split(trim, commentPattern3)[1];
                            }
                        }

                        if (string.IsNullOrWhiteSpace(trim))
                        {
                            continue;
                        }
                        string removeString = Regex.Replace(trim, stringPattern, "");

                        // /* ~ 패턴
                        if (Regex.IsMatch(trim, commentPattern2))
                        {
                            trim = Regex.Split(trim, "/*")[0];
                            // /* ~ */ 패턴이 아닌 경우
                            if (!Regex.IsMatch(trim, commentPattern))
                            {
                                commentLine = true;
                            }
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
                                Console.WriteLine("괄호끝");
                                break;
                            }
                            oldBuilder.AppendLine(line);
                        }
                        else
                        {
                            if (openBracketCount > 0)
                            {
                                found2 = true;
                            }

                        }


                    }
                    else
                    {
                        if (Regex.Match(line, $"{methodName}").Success)
                        {
                            
                            string trim = line.Trim();
                            if (trim.StartsWith("//"))
                            {
                                continue;
                            }

                            if (trim.StartsWith("/*"))
                            {
                                continue;
                            }

                            if (Regex.Match(trim, $@"""[\s]*({methodName})").Success)
                            {
                                continue;
                            }

                            if (Regex.Match(trim, $@"{methodName}\s*" + @"\{").Success)
                            {
                                if (trim.EndsWith("}"))
                                {
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
            Console.WriteLine("찾음");
            Console.WriteLine(oldBuilder.ToString());
            Console.ReadLine();

            return oldBuilder.ToString();
        }
    }
}
