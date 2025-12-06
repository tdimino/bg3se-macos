#!/usr/bin/env python3
"""
Apply Aldea styling to the original Tanit symbol SVG.

Takes the Wikipedia Tanit SVG and applies:
- Aldea warm amber/gold color palette (#FDE047 / #FBBF24)
- Glowing circle backdrop
- Glow filter effect
"""

import re
import os


def style_tanit_svg():
    """Apply Aldea styling to the original Tanit SVG."""

    # Aldea palette
    primary = "#FDE047"    # Warm gold
    secondary = "#FBBF24"  # Amber

    # Read original SVG
    with open('/tmp/tanit_original.svg', 'r') as f:
        svg_content = f.read()

    # Expand the SVG dimensions and add viewBox to properly frame the circle
    # Original: width="655" height="840"
    # Use viewBox to shift the visible area so circle is fully visible and centered
    svg_content = re.sub(r'width="655"', 'width="900"', svg_content)
    svg_content = re.sub(r'height="840"', 'height="900"', svg_content)

    # Add viewBox to show full circle - circle at (350,420) with r=450
    # Need viewBox from -150 to 850 horizontally, -80 to 920 vertically
    svg_content = re.sub(
        r'(<svg[^>]*)(>)',
        r'\1 viewBox="-150 -80 1000 1000"\2',
        svg_content,
        count=1
    )

    # Replace yellow fill with gradient reference
    svg_content = re.sub(r'fill:#ffff00', f'fill:url(#aldeaGold)', svg_content)

    # Replace stroke color
    svg_content = re.sub(r'stroke:#000000', f'stroke:{secondary}', svg_content)

    # Make stroke thinner for elegance
    svg_content = re.sub(r'stroke-width:3', 'stroke-width:2', svg_content)

    # Add our custom defs with gradient and glow filter
    custom_defs = f'''
    <!-- Aldea Tanit Styling -->
    <linearGradient id="aldeaGold" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{primary}"/>
      <stop offset="100%" stop-color="{secondary}"/>
    </linearGradient>

    <radialGradient id="glowCircle" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="{secondary}" stop-opacity="0.5"/>
      <stop offset="60%" stop-color="{secondary}" stop-opacity="0.15"/>
      <stop offset="100%" stop-color="{secondary}" stop-opacity="0"/>
    </radialGradient>

    <filter id="warmGlow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur in="SourceAlpha" stdDeviation="8" result="blur"/>
      <feFlood flood-color="{secondary}" flood-opacity="0.5" result="glowColor"/>
      <feComposite in="glowColor" in2="blur" operator="in" result="glow"/>
      <feMerge>
        <feMergeNode in="glow"/>
        <feMergeNode in="glow"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  '''

    # Insert custom defs before closing </defs> tag
    svg_content = re.sub(r'(</defs>)', custom_defs + r'\n  \1', svg_content)

    # Add glowing circle backdrop and border ring around the symbol
    # The original viewBox is 655x840, symbol group is transformed
    # Circle is enlarged to give the symbol breathing room like in the reference
    # Glow is applied to the circle, not the symbol
    # Symbol center is approximately at (350, 420) based on visual inspection
    # Circle needs to be large enough to surround the symbol with padding
    glow_backdrop = '''
  <!-- Glowing circle backdrop -->
  <ellipse cx="350" cy="420" rx="480" ry="480" fill="url(#glowCircle)"/>

  <!-- Circular border ring with glow effect -->
  <ellipse cx="350" cy="420" rx="450" ry="450"
           fill="none"
           stroke="url(#aldeaGold)"
           stroke-width="5"
           opacity="0.9"
           filter="url(#warmGlow)"/>
  <!-- Circular border ring - inner subtle -->
  <ellipse cx="350" cy="420" rx="440" ry="440"
           fill="none"
           stroke="#FBBF24"
           stroke-width="1.5"
           opacity="0.4"/>
'''
    # Insert before the main group
    svg_content = re.sub(r'(<g\s+id="g4053")', glow_backdrop + r'  \1', svg_content)

    # Don't apply glow filter to symbol - it's on the circle now

    return svg_content


def main():
    # Generate styled SVG
    styled_svg = style_tanit_svg()

    # Output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, '..', 'assets', 'tanit.svg')

    # Write to file
    with open(output_path, 'w') as f:
        f.write(styled_svg)

    print(f"Styled Tanit SVG written to: {output_path}")
    print("Applied:")
    print("  - Aldea gold gradient (#FDE047 → #FBBF24)")
    print("  - Amber stroke color (#FBBF24)")
    print("  - Glowing circle backdrop")
    print("  - Warm glow filter effect")


if __name__ == '__main__':
    main()
