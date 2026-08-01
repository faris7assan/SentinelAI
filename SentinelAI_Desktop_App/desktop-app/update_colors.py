import os
import glob

# Mapping old colors to new cyber colors
REPLACEMENTS = {
    '"#F85149"': '"#EF4444"', # red
    '"#D29922"': '"#F59E0B"', # yellow/amber
    '"#58A6FF"': '"#0EA5E9"', # blue/cyan
    '"#3FB950"': '"#10B981"', # green
    '"#8B949E"': '"#00E5FF"', # info fallback
    '"#2EA043"': '"#10B981"', # success hover/live
    'color:#58A6FF': 'color:#00E5FF',
    'color:#2EA043': 'color:#10B981',
    'color:#8B949E': 'color:#94A3B8',
    'color:#F85149': 'color:#EF4444',
    'color:#D29922': 'color:#F59E0B',
    'color:#3FB950': 'color:#10B981',
    '"#8957E5"': '"#8B5CF6"', # violet
}

def update_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    for old, new in REPLACEMENTS.items():
        content = content.replace(old, new)
        
    if content != original:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {path}")

base_dir = r"e:\Hassan INFO\Projects\SentinelAI\SentinelAI_Desktop_App\desktop-app\ui"
for root, _, files in os.walk(base_dir):
    for file in files:
        if file.endswith('.py'):
            update_file(os.path.join(root, file))

update_file(r"e:\Hassan INFO\Projects\SentinelAI\SentinelAI_Desktop_App\desktop-app\utils\styles.py")
