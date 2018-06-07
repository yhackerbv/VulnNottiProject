using System;

namespace Flicker
{
	public class TextElement : Element
	{
		public TextElement(int x, int y, int width, int height)
			: base(x, y, width, height) { }

		public TextElement(float x, float y, float width, float height)
			: base(x, y, width, height) { }

		public string Text { get; set; } = "";
		public bool Wrap { get; set; } = true;

		protected override void CustomRender()
		{
			if (!Wrap)
			{
				Console.Write(Text);
				return;
			}

			foreach (var line in Text.Chunks(Width - Padding * 4))
			{
				Console.Write(line.Trim());
				++Console.CursorTop;
				Console.CursorLeft = X + Padding * 2;
			}
		}
	}
}