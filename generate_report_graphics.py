import os
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Set up matplotlib style for academic publications (IEEE-like)
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif', 'Liberation Serif']
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['figure.titlesize'] = 13

# Create output folder
script_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(script_dir, "visuals")
os.makedirs(output_dir, exist_ok=True)

def generate_network_map():
    """Generates a professional architectural request flow and supply chain map using PIL."""
    width, height = 1000, 600
    img = Image.new('RGB', (width, height), color='#FFFFFF')
    draw = ImageDraw.Draw(img)
    
    # Try to load standard Windows fonts, fallback to default
    try:
        font_title = ImageFont.truetype("arial.ttf", 20)
        font_box_title = ImageFont.truetype("arial.ttf", 13)
        font_box_desc = ImageFont.truetype("arial.ttf", 10)
        font_label = ImageFont.truetype("arial.ttf", 11)
    except IOError:
        font_title = ImageFont.load_default()
        font_box_title = ImageFont.load_default()
        font_box_desc = ImageFont.load_default()
        font_label = ImageFont.load_default()

    # Draw grid or subtle background lines
    for x in range(0, width, 50):
        draw.line([(x, 0), (x, height)], fill='#F4F4F6', width=1)
    for y in range(0, height, 50):
        draw.line([(0, y), (width, y)], fill='#F4F4F6', width=1)

    # Color Palette
    color_client = '#3B5998'      # Blue
    color_gateway = '#1F497D'     # Dark Blue
    color_sec = '#C7254E'         # Red/Accent
    color_service = '#2E7D32'     # Green
    color_db = '#E65100'          # Orange
    color_ml = '#6A1B9A'          # Purple

    # Helper function to draw rounded boxes with text
    def draw_box(x, y, w, h, title, desc_lines, fill_color):
        # Draw shadow
        draw.rounded_rectangle([x+4, y+4, x+w+4, y+h+4], radius=8, fill='#E0E0E0')
        # Draw main box
        draw.rounded_rectangle([x, y, x+w, y+h], radius=8, fill=fill_color, outline='#333333', width=1)
        # Write Title
        draw.text((x + 12, y + 10), title, fill='#FFFFFF', font=font_box_title)
        # Write Descriptions
        curr_y = y + 30
        for line in desc_lines:
            draw.text((x + 12, curr_y), line, fill='#F5F5F5', font=font_box_desc)
            curr_y += 14

    # Defining nodes (x, y, w, h)
    nodes = {
        'client': (30, 180, 160, 80, 'Client Browser / App', ['• Initiates API Request', '• JWT Bearer Token', '• HTTPS Transport'], color_client),
        'gateway': (250, 180, 180, 80, 'Kong API Gateway', ['• Central Ingress/Proxy', '• Rate Limiting (Redis)', '• Path Routing'], color_gateway),
        'ebpf': (250, 340, 180, 80, 'eBPF Sensor Layer', ['• Kernel-Level Intercept', '• Non-Intrusive Tap', '• Packet Mirroring'], color_sec),
        'ml': (250, 500, 180, 80, 'ML Anomaly Engine', ['• Out-of-Band Analysis', '• Isolation Forest', '• Threat Profiling'], color_ml),
        'sidecar': (500, 180, 190, 80, 'Security Middleware', ['• BOLA Ownership Check', '• Egress DLP Filter', '• Mass Assignment Block'], color_sec),
        'service': (760, 180, 180, 80, 'Target Microservice', ['• Application Business', '• FastAPI Backend', '• Executes Request'], color_service),
        'database': (760, 340, 180, 80, 'Database Layer', ['• Encrypted Storage', '• User Records', '• Audit Trail'], color_db)
    }

    # Draw all boxes
    for key, val in nodes.items():
        draw_box(val[0], val[1], val[2], val[3], val[4], val[5], val[6])

    # Helper function to draw dynamic arrows
    def draw_arrow(start, end, label_text="", align='h'):
        x1, y1 = start
        x2, y2 = end
        draw.line([start, end], fill='#333333', width=2)
        # Draw Arrowhead
        if align == 'h':
            draw.polygon([(x2, y2), (x2-8, y2-5), (x2-8, y2+5)], fill='#333333')
            if label_text:
                draw.text((x1 + 10, y1 - 16), label_text, fill='#333333', font=font_label)
        elif align == 'v':
            draw.polygon([(x2, y2), (x2-5, y2-8), (x2+5, y2-8)], fill='#333333')
            if label_text:
                draw.text((x1 + 8, y1 + 15), label_text, fill='#333333', font=font_label)

    # Draw connections
    draw_arrow((190, 220), (250, 220), "1. HTTPS POST / GET", 'h')
    draw_arrow((430, 220), (500, 220), "3. Forward", 'h')
    draw_arrow((690, 220), (760, 220), "4. Scanned", 'h')
    
    # Gateway to eBPF tap
    draw_arrow((340, 260), (340, 340), "2. eBPF Tap (Mirror)", 'v')
    # eBPF to ML Anomaly Engine
    draw_arrow((340, 420), (340, 500), "Async Mirroring", 'v')
    
    # Microservice to DB
    draw_arrow((850, 260), (850, 340), "5. DB Query", 'v')

    # Draw Title block inside image
    draw.text((30, 30), "MazAPI: Production Enterprise Request Flow & Security Architecture", fill='#1F497D', font=font_title)
    draw.line([(30, 60), (970, 60)], fill='#1F497D', width=2)

    # Legends & Metadata block
    draw.rectangle([700, 500, 970, 580], fill='#F8F9FA', outline='#CCCCCC')
    draw.text((710, 505), "Key Architecture Properties:", fill='#333333', font=font_box_desc)
    draw.text((710, 520), "- Inline Controls: Gateway + Authorizer Sidecar", fill='#555555', font=font_box_desc)
    draw.text((710, 535), "- Out-of-Band Controls: eBPF Tap + ML Engine", fill='#555555', font=font_box_desc)
    draw.text((710, 550), "- Fail-Safe: eBPF failure does not crash the API", fill='#555555', font=font_box_desc)
    draw.text((710, 565), "- Storage: Enforced data sanitization at rest", fill='#555555', font=font_box_desc)

    img.save(os.path.join(output_dir, "network_map.png"), dpi=(300, 300))
    print("Successfully generated: network_map.png")

def generate_latency_graph():
    """Generates the response latency comparison graph between deployment architectures."""
    fig, ax = plt.subplots(figsize=(6, 3.5), layout='constrained')
    
    architectures = [
        'Direct API\n(No Security)', 
        'Inline API + Middleware\n(DLP & JWT Authorizer)', 
        'eBPF Out-of-Band\n+ ML Monitoring'
    ]
    latencies = [15.2, 18.7, 15.3] # In milliseconds
    colors = ['#CCCCCC', '#C7254E', '#1F497D']
    
    bars = ax.bar(architectures, latencies, color=colors, edgecolor='#333333', width=0.55)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.1f} ms',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')

    ax.set_ylabel('Mean Latency (ms)', fontweight='bold')
    ax.set_title('API Response Latency Overhead Comparison (10,000 requests)', pad=15, fontweight='bold', color='#1F497D')
    ax.set_ylim(0, 24)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Annotate performance cost
    ax.text(1, 20.5, '+23.0% Latency Overhead\n(Inline processing block)', ha='center', color='#C7254E', fontsize=8, bbox=dict(boxstyle="round,pad=0.3", fc="#FFF5F5", ec="#C7254E", lw=0.5))
    ax.text(2, 17.5, '+0.6% Latency Overhead\n(Zero-latency tap)', ha='center', color='#1F497D', fontsize=8, bbox=dict(boxstyle="round,pad=0.3", fc="#F0F4F8", ec="#1F497D", lw=0.5))

    fig.savefig(os.path.join(output_dir, "latency_comparison.png"), dpi=300)
    plt.close(fig)
    print("Successfully generated: latency_comparison.png")

def generate_ml_metrics():
    """Generates the ML metrics and precision-recall curve graph."""
    fig, ax = plt.subplots(figsize=(6, 3.5), layout='constrained')
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [97.10, 96.80, 97.50, 97.14]
    
    bars = ax.barh(metrics, values, color='#3B5998', edgecolor='#333333', height=0.5)
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{width:.2f}%',
                    xy=(width - 10, bar.get_y() + bar.get_height() / 2),
                    xytext=(0, 0),
                    textcoords="offset points",
                    ha='right', va='center', color='white', fontweight='bold')

    ax.set_xlabel('Score (%)', fontweight='bold')
    ax.set_title('MazAPI ML Engine Anomaly Detection Performance', pad=15, fontweight='bold', color='#1F497D')
    ax.set_xlim(0, 110)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    fig.savefig(os.path.join(output_dir, "ml_metrics.png"), dpi=300)
    plt.close(fig)
    print("Successfully generated: ml_metrics.png")

def generate_vulnerability_mitigation():
    """Generates vulnerability exposure chart before/after controls."""
    fig, ax = plt.subplots(figsize=(6, 4), layout='constrained')
    
    vulns = [
        'Injection (SQLi/XSS)',
        'Broken Object Auth (BOLA)',
        'Broken User Auth (JWT)',
        'Mass Assignment',
        'Security Misconfig.'
    ]
    before = [8.5, 9.2, 7.8, 7.0, 6.5]
    after = [0.2, 0.1, 0.0, 0.2, 0.5]
    
    y = np.arange(len(vulns))
    width = 0.35
    
    rects1 = ax.barh(y - width/2, before, width, label='Legacy (No Controls)', color='#C7254E', edgecolor='#333333')
    rects2 = ax.barh(y + width/2, after, width, label='MazAPI Defended', color='#2E7D32', edgecolor='#333333')
    
    ax.set_xlabel('Vulnerability Exposure Index (0-10, Higher is Worse)', fontweight='bold')
    ax.set_title('OWASP Top 10 API Exposure Scores Comparison', pad=15, fontweight='bold', color='#1F497D')
    ax.set_yticks(y)
    ax.set_yticklabels(vulns, fontweight='bold')
    ax.legend(frameon=True)
    ax.set_xlim(0, 11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    fig.savefig(os.path.join(output_dir, "vulnerability_mitigation.png"), dpi=300)
    plt.close(fig)
    print("Successfully generated: vulnerability_mitigation.png")

if __name__ == '__main__':
    generate_network_map()
    generate_latency_graph()
    generate_ml_metrics()
    generate_vulnerability_mitigation()
