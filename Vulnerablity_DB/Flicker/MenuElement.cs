using System;
using System.Collections.Generic;

namespace Flicker
{
	public class MenuElement : Element
	{
		public MenuElement(int x, int y, int width, int height)
			: base(x, y, width, height) { }

		public MenuElement(float x, float y, float width, float height)
			: base(x, y, width, height) { }

		public List<MenuItem> Items { get; set; } = new List<MenuItem>();
		private int SelectedIndex { get; set; }

		public override void HandleKey(ConsoleKeyInfo key)
		{
			switch (key.Key)
			{
				case ConsoleKey.UpArrow:
					SelectedIndex = (--SelectedIndex).Wrap(0, Items.Count - 1);
					break;

				case ConsoleKey.DownArrow:
					SelectedIndex = (++SelectedIndex).Wrap(0, Items.Count - 1);
					break;

				case ConsoleKey.Enter:
					Items[SelectedIndex].Method();
					break;
			}
		}

		protected override void CustomRender()
		{
			for (var i = 0; i < Items.Count; ++i)
			{
				Console.BackgroundColor = Background;
				Console.ForegroundColor = Foreground;

				if (i == SelectedIndex)
				{
					Console.BackgroundColor = ConsoleColor.DarkGray;
					Console.ForegroundColor = ConsoleColor.White;
				}

				Console.Write(Items[i].Label);
				++Console.CursorTop;
				Console.CursorLeft = X + Padding * 2;
			}
		}
	}

	public class MenuItem
	{
		public Action Method { get; set; }
		public string Label { get; set; }
	}
}