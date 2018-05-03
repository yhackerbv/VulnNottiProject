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
        protected override string RegexFuncPattern => $@"@@ \-(?<{OldStart}>\d+),(?<{OldLines}>\d+) \+(?<{NewStart}>\d+),(?<{NewLines}>\d+) @@ (?<{MethodName}>.+)";

        protected override string Extension => ".c";

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
                int defSpace = 0;
                while (!reader.EndOfStream) {

                    string line = reader.ReadLine();
                    if (defSpace > 0) {
                        if (line.Length < defSpace) {
                            continue;
                        }
                        string concat = line.Substring(0, defSpace);
                        if (string.IsNullOrWhiteSpace(concat)) {
                            string trim = line.Trim();
                            // #으로 시작한다면 주석이니 제거
                            if (trim.StartsWith("#")) {
                                continue;
                            }
                            oldBuilder.AppendLine(line);
                        } else {
                            continue;
                        }
                    }
                    if (Regex.Match(line, $@"{methodName}").Success) {
                        
                        defSpace = line.IndexOf(methodName);
                        oldBuilder.AppendLine(line);
                    }

                }

            }
            return oldBuilder.ToString();
        }
    }
}
