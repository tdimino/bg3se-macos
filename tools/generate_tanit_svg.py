#!/usr/bin/env python3
"""
Generate a styled Tanit symbol SVG matching the Aldea/Twilio-Aldea aesthetic.

Colors: #FDE047 (primary gold) and #FBBF24 (secondary amber)
Style: Warm glow with radial gradient backdrop
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom


def generate_tanit_svg(width=80, height=100):
    """Generate the Tanit symbol SVG."""

    # Colors from Aldea palette
    primary = "#FDE047"   # Warm gold
    secondary = "#FBBF24"  # Amber
    glow_color = "rgba(251, 191, 36, 0.4)"  # Amber glow

    # Create SVG root
    svg = ET.Element('svg')
    svg.set('width', str(width))
    svg.set('height', str(height))
    svg.set('viewBox', f'0 0 {width} {height}')
    svg.set('xmlns', 'http://www.w3.org/2000/svg')

    # Add title for accessibility
    title = ET.SubElement(svg, 'title')
    title.text = 'Symbol of Tanit - Aldea'

    # Defs section for gradients and filters
    defs = ET.SubElement(svg, 'defs')

    # Linear gradient for main symbol
    gradient = ET.SubElement(defs, 'linearGradient')
    gradient.set('id', 'tanitGold')
    gradient.set('x1', '0%')
    gradient.set('y1', '0%')
    gradient.set('x2', '0%')
    gradient.set('y2', '100%')

    stop1 = ET.SubElement(gradient, 'stop')
    stop1.set('offset', '0%')
    stop1.set('stop-color', primary)

    stop2 = ET.SubElement(gradient, 'stop')
    stop2.set('offset', '100%')
    stop2.set('stop-color', secondary)

    # Radial gradient for glow backdrop
    radial = ET.SubElement(defs, 'radialGradient')
    radial.set('id', 'glowBackdrop')
    radial.set('cx', '50%')
    radial.set('cy', '30%')
    radial.set('r', '50%')

    rstop1 = ET.SubElement(radial, 'stop')
    rstop1.set('offset', '0%')
    rstop1.set('stop-color', secondary)
    rstop1.set('stop-opacity', '0.5')

    rstop2 = ET.SubElement(radial, 'stop')
    rstop2.set('offset', '70%')
    rstop2.set('stop-color', secondary)
    rstop2.set('stop-opacity', '0.1')

    rstop3 = ET.SubElement(radial, 'stop')
    rstop3.set('offset', '100%')
    rstop3.set('stop-color', secondary)
    rstop3.set('stop-opacity', '0')

    # Drop shadow filter for warm glow
    filter_elem = ET.SubElement(defs, 'filter')
    filter_elem.set('id', 'warmGlow')
    filter_elem.set('x', '-50%')
    filter_elem.set('y', '-50%')
    filter_elem.set('width', '200%')
    filter_elem.set('height', '200%')

    blur = ET.SubElement(filter_elem, 'feGaussianBlur')
    blur.set('in', 'SourceAlpha')
    blur.set('stdDeviation', '3')
    blur.set('result', 'blur')

    flood = ET.SubElement(filter_elem, 'feFlood')
    flood.set('flood-color', secondary)
    flood.set('flood-opacity', '0.6')
    flood.set('result', 'glowColor')

    composite = ET.SubElement(filter_elem, 'feComposite')
    composite.set('in', 'glowColor')
    composite.set('in2', 'blur')
    composite.set('operator', 'in')
    composite.set('result', 'glow')

    merge = ET.SubElement(filter_elem, 'feMerge')
    merge_glow = ET.SubElement(merge, 'feMergeNode')
    merge_glow.set('in', 'glow')
    merge_src = ET.SubElement(merge, 'feMergeNode')
    merge_src.set('in', 'SourceGraphic')

    # Calculate positions
    cx = width / 2  # Center X
    circle_y = 18
    circle_r = 10
    bar_y = 33
    bar_h = 4
    body_top = 39
    body_bottom = 76
    bottom_bar_y = 80

    # Glow backdrop ellipse
    glow_bg = ET.SubElement(svg, 'ellipse')
    glow_bg.set('cx', str(cx))
    glow_bg.set('cy', str(height * 0.4))
    glow_bg.set('rx', str(width * 0.45))
    glow_bg.set('ry', str(height * 0.35))
    glow_bg.set('fill', 'url(#glowBackdrop)')

    # Main symbol group
    symbol = ET.SubElement(svg, 'g')
    symbol.set('fill', 'url(#tanitGold)')
    symbol.set('stroke', secondary)
    symbol.set('stroke-width', '1.5')
    symbol.set('filter', 'url(#warmGlow)')

    # Circle (disc/sun) - top center
    circle = ET.SubElement(symbol, 'circle')
    circle.set('cx', str(cx))
    circle.set('cy', str(circle_y))
    circle.set('r', str(circle_r))

    # Crescent horns - curved arms extending from sides
    # Left horn
    left_horn = ET.SubElement(symbol, 'path')
    left_horn.set('d', f'M {cx - circle_r - 1} {circle_y} Q {cx - circle_r - 12} {circle_y - 10}, {cx - circle_r - 18} {circle_y + 6}')
    left_horn.set('fill', 'none')
    left_horn.set('stroke-width', '3')
    left_horn.set('stroke-linecap', 'round')

    # Right horn
    right_horn = ET.SubElement(symbol, 'path')
    right_horn.set('d', f'M {cx + circle_r + 1} {circle_y} Q {cx + circle_r + 12} {circle_y - 10}, {cx + circle_r + 18} {circle_y + 6}')
    right_horn.set('fill', 'none')
    right_horn.set('stroke-width', '3')
    right_horn.set('stroke-linecap', 'round')

    # Horizontal bar below circle
    bar1 = ET.SubElement(symbol, 'rect')
    bar1.set('x', str(cx - 22))
    bar1.set('y', str(bar_y))
    bar1.set('width', '44')
    bar1.set('height', str(bar_h))
    bar1.set('rx', '1')

    # Triangular body (trapezoid)
    body = ET.SubElement(symbol, 'path')
    body_top_w = 8
    body_bottom_w = 16
    body.set('d', f'M {cx - body_top_w} {body_top} L {cx + body_top_w} {body_top} L {cx + body_bottom_w} {body_bottom} L {cx - body_bottom_w} {body_bottom} Z')

    # Bottom horizontal bar
    bar2 = ET.SubElement(symbol, 'rect')
    bar2.set('x', str(cx - 24))
    bar2.set('y', str(bottom_bar_y))
    bar2.set('width', '48')
    bar2.set('height', str(bar_h))
    bar2.set('rx', '1')

    return svg


def prettify(elem):
    """Return a pretty-printed XML string for the Element."""
    rough_string = ET.tostring(elem, encoding='unicode')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")[23:]  # Skip XML declaration


def main():
    import os

    # Generate SVG
    svg = generate_tanit_svg(80, 100)

    # Output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, '..', 'assets', 'tanit.svg')

    # Write to file
    with open(output_path, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(prettify(svg))

    print(f"Generated Tanit SVG at: {output_path}")
    print("Colors: #FDE047 (primary) / #FBBF24 (secondary)")
    print("Style: Warm glow effect with radial gradient backdrop")


if __name__ == '__main__':
    main()
