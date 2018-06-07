using System;

namespace Flicker
{
	internal static class Tools
	{
		public static T Clamp<T>(this T val, T min)
			where T : IComparable<T> =>
			val.CompareTo(min) < 0
				? min
				: val;

		public static T Clamp<T>(this T val, T min, T max)
			where T : IComparable<T> =>
			val.CompareTo(min) < 0
				? min
				: val.CompareTo(max) > 0
					? max
					: val;

		public static T Wrap<T>(this T val, T min, T max)
			where T : IComparable<T> =>
			val.CompareTo(min) < 0
				? max
				: val.CompareTo(max) > 0
					? min
					: val;

		public static class Console
		{
			public static void WriteAt(int x, int y, string str)
			{
				System.Console.CursorLeft = x;
				System.Console.CursorTop = y;
				System.Console.Write(str);
			}

			public static void WriteAt(int x, int y, string str, ConsoleColor colour)
			{
				var old = System.Console.ForegroundColor;
				System.Console.ForegroundColor = colour;
				WriteAt(x, y, str);
				System.Console.ForegroundColor = old;
			}

			public static void Fill(int x, int y, int width, int height, char c)
			{
				for (var i = x; i < x + width; ++i)
					for (var j = y; j < y + height; ++j)
						WriteAt(i, j, c.ToString());
			}

			public static void Fill(int x, int y, int width, int height, char c, ConsoleColor colour)
			{
				var old = System.Console.ForegroundColor;
				System.Console.ForegroundColor = colour;
				Fill(x, y, width, height, c);
				System.Console.ForegroundColor = old;
			}
		}
	}
}