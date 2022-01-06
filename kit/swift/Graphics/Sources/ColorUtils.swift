// Given an opaque foreground and background color, try to return a foreground
// color that is "readable" over the background color by luma-inverting the
// foreground color and then picking whichever foreground color has higher
// contrast against the background color.  You should not pass colors with
// non-255 alpha to this routine, since determining the correct behavior in such
// cases can be impossible.
//

public class ColorUtils {
  
  public static var isInvertedColorScheme: Bool {
    return false
  }

  // public static func blendTowardOppositeLuma(color: Color, alpha: Alpha) -> Color {
  //   return AlphaBlend(isDark(color) ? Color.White : Color.Black, color, alpha)
  // }

  public static func getReadableColor(foreground: Color, background: Color) -> Color {
    return Color()
  }

  public static func deriveDefaultIconColor(textColor: Color) -> Color {
    //return ColorUtils.blendTowardOppositeLuma(textColor, 0x4c)
    return textColor
  }
  
}