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

        protected override string RegexFuncPattern => $@"@@ \-(?<{OldStart}>\d+),(?<{OldLines}>\d+) \+(?<{NewStart}>\d+),(?<{NewLines}>\d+) @@ (?<{MethodName}>(static)? [\w]+ [\w]+)\([\w \*\,\t\n]*\)";

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
            using (var reader = new StreamReader(oldStream)) {
                
                bool found = false;
                int bracketCount = -1;
                while (!reader.EndOfStream) {
                    string line = reader.ReadLine();

                    if (found)
                    {

                        int openBracketCount = line.Count(c => c == '{');
                        int closeBracketCount = line.Count(c => c == '}');

                        if (bracketCount == -1)
                        {

                        }
                        if (line.Count(c => c == '{') > 0)
                        {

                        }
                    }

                    if (Regex.Match(line, $@"{methodName}").Success) {
                        found = true;
                        int openBracketCount = line.Count(c => c == '{');
                        int closeBracketCount = line.Count(c => c == '}');
                        int subtract = openBracketCount - closeBracketCount;
                        oldBuilder.AppendLine(line);

                        if (subtract < 0)
                        {
                            break;
                        }
                        bracketCount = subtract;
                    }

                }

            }
            return oldBuilder.ToString();
        }
    }
}
