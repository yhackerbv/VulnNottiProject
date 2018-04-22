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

        protected override string RegexFuncPattern => throw new NotImplementedException();

        protected override string Extension => throw new NotImplementedException();

        public override MatchCollection GetMatches(string patchCode) {
            throw new NotImplementedException();
        }

        public override string RemoveComment(string original) {
            throw new NotImplementedException();
        }

        protected override string GetOriginalFunc(Stream oldStream, string methodName) {
            throw new NotImplementedException();
        }
    }
}
