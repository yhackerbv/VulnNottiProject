using System;

namespace Flicker
{
	public class InputElement : Element
	{
		public InputElement(out string result, string label)
			: base(0, 0, 0, 0)
		{
			Visible = false;
			Console.Clear();
			Tools.Console.Fill(0, 1, Console.BufferWidth, Console.BufferHeight - 2, '\u2588');
			Tools.Console.WriteAt(0, 0, label);
			result = Console.ReadLine();
		}
	}

	public class InputElement<T> : Element
	{
		public InputElement(out T result, string label)
			: base(0, 0, 0, 0)
		{
			Visible = false;
			Console.Clear();
			Tools.Console.Fill(0, 1, Console.BufferWidth, Console.BufferHeight - 2, '\u2588');
			Tools.Console.WriteAt(0, 0, label);

			var input = Console.ReadLine();

			try
			{
				result = (T)Convert.ChangeType(input, typeof(T));
			}
			catch
			{
				// Fail silently
				result = default(T);
			}
		}
	}
}