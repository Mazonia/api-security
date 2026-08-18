import os
import re
import json

def analyze_all():
    print("================ MAZAPI CURRENT CAPABILITIES ================")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Extension
    popup_html_path = os.path.join(base_dir, 'mazapi-extension', 'popup.html')
    with open(popup_html_path, 'r', encoding='utf-8', errors='replace') as f:
        html = f.read()
    tabs = re.findall(r'data-tab=[\'"]([^\'"]+)[\'"][^>]*>([^<]+)<', html)
    print("Extension Tabs:", [(t[0], t[1].strip()) for t in tabs])
    
    # 2. Testing engine
    te_path = os.path.join(base_dir, 'api-security-project', 'testing-engine')
    print("Testing Engine Files:", os.listdir(te_path))
    owasp_path = os.path.join(te_path, 'owasp_tests')
    print("OWASP Test Modules:", os.listdir(owasp_path))
    
    # 3. VSCode extension
    vscode_path = os.path.join(base_dir, 'mazapi-vscode', 'src')
    print("VSCode src Files:", os.listdir(vscode_path))
    
    # 4. Monitoring & ML models
    mon_path = os.path.join(base_dir, 'api-security-project', 'monitoring')
    print("Monitoring Files:", os.listdir(mon_path))
    data_path = os.path.join(base_dir, 'api-security-project', 'data')
    print("Data Files:", os.listdir(data_path))

if __name__ == '__main__':
    analyze_all()
