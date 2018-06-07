using System;

namespace Flicker
{
	public abstract class Element : IRenderable
	{
		public readonly int Height;
		public readonly int Width;
		public readonly int X;
		public readonly int Y;

		protected Element(int x, int y, int width, int height)
		{
			X = x;
			Y = y;
			Width = width;
			Height = height;
		}

		protected Element(float x, float y, float width, float height)
		{
			x = x.Clamp(0, .99f);
			y = y.Clamp(0, .99f);
			width = width.Clamp(0, .99f);
			height = height.Clamp(0, .99f);

			X = (int)(Console.BufferWidth * x);
			Y = (int)(Console.BufferHeight * y);
			Width = (int)(Console.BufferWidth * width);
			Height = (int)(Console.BufferHeight * height);
		}

		public bool Visible { get; set; } = true;
		public char Border { get; set; } = ' ';
		public int Padding { get; set; } = 1; // Must be at least 1 (to make room for header), TODO enforce this
		public ConsoleColor Foreground { get; set; } = ConsoleColor.White;
		public ConsoleColor Background { get; set; } = ConsoleColor.Black;
		public Renderer AssociatedRenderer { get; set; }

		public virtual void HandleKey(ConsoleKeyInfo key) { }

		/// <summary>
		///     Draw this element
		/// </summary>
		void IRenderable.Render(bool selected)
		{
			if (!Visible) return;

			Console.ForegroundColor = Foreground;
			Console.BackgroundColor = Background;
			Console.CursorLeft = X;
			Console.CursorTop = Y;

			Tools.Console.Fill(
				X,
				Y,
				Width,
				Height,
				' '
			);

			if (Border != ' ')
			{
				// Top and bottom borders
				Console.CursorLeft = X;
				Console.CursorTop = Y;
				Console.Write(new string(Border, Width));
				Console.CursorLeft = X;
				Console.CursorTop = Y + Height - 1;
				Console.Write(new string(Border, Width));

				// Left and right borders
				for (var y = Y; y < Y + Height - 1; ++y)
				{
					Tools.Console.WriteAt(X, y, Border.ToString());
					Tools.Console.WriteAt(X + Width - 1, y, Border.ToString());
				}
			}

			if (selected)
				Tools.Console.WriteAt(
					X, Y,
					new string('\u2580', Width),
					ConsoleColor.Red
				);

			Console.CursorLeft = X + Padding * 2;
			Console.CursorTop = Y + Padding;

			CustomRender();

			Console.ResetColor();
		}

		public void Select() => AssociatedRenderer.Select(this);

		public void Destroy() => AssociatedRenderer.Destroy(this);

		protected virtual void CustomRender() { }
	}
}