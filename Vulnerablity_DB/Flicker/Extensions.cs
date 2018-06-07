using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Flicker
{
	internal static class Extensions
	{
		internal static IEnumerable<string> Chunks(this string str, int size)
		{
			return Regex.Matches(str, "(.{1," + size + "})").Cast<Match>().Select(m => m.Value);
		}
	}
}