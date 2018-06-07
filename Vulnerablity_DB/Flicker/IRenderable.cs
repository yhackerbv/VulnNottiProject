using System;

namespace Flicker
{
	public interface IRenderable
	{
		Renderer AssociatedRenderer { get; set; }

		void Render(bool selected);

		void HandleKey(ConsoleKeyInfo key);

		void Select();

		void Destroy();
	}
}