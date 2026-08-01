import re
import os
import docx
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_styled_paragraph(doc, text="", style='Normal', space_after=6, space_before=0, line_spacing=1.5, align=WD_ALIGN_PARAGRAPH.LEFT):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.line_spacing = line_spacing
    return p

def format_run(run, font_name="Times New Roman", font_size=12, bold=False, italic=False, color=None):
    run.font.name = font_name
    run.font.size = Pt(font_size)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color

def parse_inline_markdown(paragraph, text, font_name="Times New Roman", font_size=12, base_color=None):
    # Regex to handle **bold**, *italic*, `code`, math $...$
    pattern = re.compile(r'(\*\*.*?\*\*|\*.*?\*|`.*?`|\$.*?\$|\[.*?\]\(.*?\))')
    tokens = pattern.split(text)
    
    for token in tokens:
        if not token:
            continue
        if token.startswith('**') and token.endswith('**'):
            content = token[2:-2]
            r = paragraph.add_run(content)
            format_run(r, font_name=font_name, font_size=font_size, bold=True, color=base_color)
        elif token.startswith('*') and token.endswith('*'):
            content = token[1:-1]
            r = paragraph.add_run(content)
            format_run(r, font_name=font_name, font_size=font_size, italic=True, color=base_color)
        elif token.startswith('`') and token.endswith('`'):
            content = token[1:-1]
            r = paragraph.add_run(content)
            format_run(r, font_name="Consolas", font_size=11.5, color=RGBColor(199, 37, 78))
        elif token.startswith('$') and token.endswith('$'):
            content = token.strip('$')
            r = paragraph.add_run(content)
            format_run(r, font_name="Times New Roman", font_size=font_size, italic=True, color=base_color)
        elif token.startswith('[') and ']' in token:
            match = re.match(r'\[(.*?)\]\((.*?)\)', token)
            if match:
                link_text, link_url = match.groups()
                r = paragraph.add_run(link_text)
                format_run(r, font_name=font_name, font_size=font_size, color=RGBColor(0, 102, 204), italic=True)
            else:
                r = paragraph.add_run(token)
                format_run(r, font_name=font_name, font_size=font_size, color=base_color)
        else:
            r = paragraph.add_run(token)
            format_run(r, font_name=font_name, font_size=font_size, color=base_color)

def build_docx(md_filepath, docx_filepath):
    doc = Document()
    
    # Configure Page Margins: Left 4cm (1.57 inches), Top/Bottom/Right 1 inch (2.54 cm)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.57) # 4cm for binding as requested in UMaT guidelines
        section.right_margin = Inches(1.0)

    # Set base Normal style font
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)

    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False
    code_block_lines = []
    in_table = False
    table_lines = []

    def flush_table(lines):
        if not lines:
            return
        # Parse table rows
        rows_data = []
        for l in lines:
            if re.match(r'^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$', l):
                continue # Header separator line
            parts = [p.strip() for p in l.strip().strip('|').split('|')]
            rows_data.append(parts)
        if not rows_data:
            return
        
        num_cols = max(len(r) for r in rows_data)
        table = doc.add_table(rows=len(rows_data), cols=num_cols)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = True

        for i, row in enumerate(rows_data):
            for j, cell_text in enumerate(row):
                if j < num_cols:
                    cell = table.cell(i, j)
                    cell.text = ""
                    set_cell_margins(cell, top=120, bottom=120, left=150, right=150)
                    p = cell.paragraphs[0]
                    p.paragraph_format.space_after = Pt(4)
                    p.paragraph_format.line_spacing = 1.15
                    
                    if i == 0: # Header Row
                        set_cell_background(cell, "1F497D") # Dark Blue
                        parse_inline_markdown(p, cell_text, font_name="Times New Roman", font_size=12, base_color=RGBColor(255, 255, 255))
                    else: # Data Rows
                        bg = "F2F5F9" if i % 2 == 1 else "FFFFFF"
                        set_cell_background(cell, bg)
                        parse_inline_markdown(p, cell_text, font_name="Times New Roman", font_size=12)
        
        # Add spacing after table
        doc.add_paragraph().paragraph_format.space_after = Pt(12)

    def flush_code_block(lines):
        if not lines:
            return
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.cell(0, 0)
        set_cell_background(cell, "F8F9FA")
        set_cell_margins(cell, top=150, bottom=150, left=200, right=200)
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.15
        
        code_text = "".join(lines)
        r = p.add_run(code_text)
        format_run(r, font_name="Consolas", font_size=11.5, color=RGBColor(40, 40, 40))
        doc.add_paragraph().paragraph_format.space_after = Pt(12)

    i = 0
    while i < len(lines):
        line = lines[i]

        # Handle Code Blocks
        if line.startswith('```'):
            if in_code_block:
                flush_code_block(code_block_lines)
                code_block_lines = []
                in_code_block = False
            else:
                if in_table:
                    flush_table(table_lines)
                    table_lines = []
                    in_table = False
                in_code_block = True
            i += 1
            continue

        if in_code_block:
            code_block_lines.append(line)
            i += 1
            continue

        # Handle Tables
        if line.strip().startswith('|'):
            if not in_table:
                in_table = True
            table_lines.append(line)
            i += 1
            continue
        else:
            if in_table:
                flush_table(table_lines)
                table_lines = []
                in_table = False

        # Blank Lines
        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        # Horizontal Rule
        if stripped in ['---', '***', '___']:
            p = add_styled_paragraph(doc, space_after=18, space_before=12)
            r = p.add_run("_________________________________________________________________________________")
            format_run(r, font_size=9, color=RGBColor(180, 180, 180))
            i += 1
            continue

        # Headings
        if stripped.startswith('# '):
            p = add_styled_paragraph(doc, space_after=18, space_before=24, align=WD_ALIGN_PARAGRAPH.CENTER)
            parse_inline_markdown(p, stripped[2:], font_size=18, base_color=RGBColor(31, 73, 125))
            for run in p.runs:
                run.bold = True
        elif stripped.startswith('## '):
            if stripped[3:].startswith('Chapter') or stripped[3:].startswith('References') or stripped[3:].startswith('Appendices'):
                p = doc.add_paragraph()
                p.add_run().add_break(WD_BREAK.PAGE)
            p = add_styled_paragraph(doc, space_after=18, space_before=24)
            parse_inline_markdown(p, stripped[3:], font_size=15, base_color=RGBColor(31, 73, 125))
            for run in p.runs:
                run.bold = True
        elif stripped.startswith('### '):
            p = add_styled_paragraph(doc, space_after=12, space_before=18)
            parse_inline_markdown(p, stripped[4:], font_size=13, base_color=RGBColor(59, 89, 152))
            for run in p.runs:
                run.bold = True
        elif stripped.startswith('#### '):
            p = add_styled_paragraph(doc, space_after=10, space_before=12)
            parse_inline_markdown(p, stripped[5:], font_size=12, base_color=RGBColor(51, 51, 51))
            for run in p.runs:
                run.bold = True
                run.italic = True
        # Bullet list items
        elif stripped.startswith('- ') or stripped.startswith('* ') or re.match(r'^\d+\.\s', stripped):
            p = add_styled_paragraph(doc, space_after=8, line_spacing=1.5)
            p.paragraph_format.left_indent = Inches(0.25)
            
            if stripped.startswith('- ') or stripped.startswith('* '):
                r_bullet = p.add_run("• ")
                format_run(r_bullet, font_size=12, bold=True)
                content = stripped[2:]
            else:
                match = re.match(r'^(\d+\.)\s*(.*)', stripped)
                r_bullet = p.add_run(match.group(1) + " ")
                format_run(r_bullet, font_size=12, bold=True)
                content = match.group(2)
            
            parse_inline_markdown(p, content, font_size=12)
        # Blockquote / Figure Caption / Standard Paragraph
        elif stripped.startswith('> '):
            p = add_styled_paragraph(doc, space_after=10, space_before=6, line_spacing=1.3)
            p.paragraph_format.left_indent = Inches(0.4)
            parse_inline_markdown(p, stripped[2:], font_size=11, base_color=RGBColor(80, 80, 80))
            for run in p.runs:
                run.italic = True
        elif stripped.startswith('!['): # Image placeholder / caption
            match = re.match(r'^!\[(.*?)\]\((.*?)\)', stripped)
            if match:
                caption, img_rel_path = match.groups()
                md_dir = os.path.dirname(os.path.abspath(md_filepath))
                img_path = os.path.join(md_dir, img_rel_path.replace('/', os.sep))
                
                if os.path.exists(img_path):
                    # Add centered image
                    p_img = doc.add_paragraph()
                    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p_img.paragraph_format.space_before = Pt(12)
                    p_img.paragraph_format.space_after = Pt(6)
                    r_img = p_img.add_run()
                    r_img.add_picture(img_path, width=Inches(5.5))
                    
                    # Add centered caption
                    p_cap = add_styled_paragraph(doc, space_after=12, space_before=4, align=WD_ALIGN_PARAGRAPH.CENTER)
                    r_cap = p_cap.add_run(f"Figure: {caption}")
                    format_run(r_cap, font_size=10.5, italic=True, color=RGBColor(100, 100, 100))
                else:
                    p = add_styled_paragraph(doc, space_after=12, space_before=6, align=WD_ALIGN_PARAGRAPH.CENTER)
                    parse_inline_markdown(p, stripped, font_size=10.5, base_color=RGBColor(100, 100, 100))
                    for run in p.runs:
                        run.italic = True
            else:
                p = add_styled_paragraph(doc, space_after=12, space_before=6, align=WD_ALIGN_PARAGRAPH.CENTER)
                parse_inline_markdown(p, stripped, font_size=10.5, base_color=RGBColor(100, 100, 100))
                for run in p.runs:
                    run.italic = True
        else:
            p = add_styled_paragraph(doc, space_after=10, space_before=0, line_spacing=1.5)
            parse_inline_markdown(p, stripped, font_size=12)

        i += 1

    doc.save(docx_filepath)
    print(f"Document successfully created: {docx_filepath}")

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    md_path = os.path.join(script_dir, "MazAPI_Final_Report.md")
    docx_path = os.path.join(script_dir, "MazAPI_Final_Report.docx")
    build_docx(md_path, docx_path)
