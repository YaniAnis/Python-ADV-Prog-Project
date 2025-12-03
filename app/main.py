"""
PenTest MultiTools - Main Application Entry Point
Advanced Cybersecurity Testing Suite for Educational Purposes
"""

import sys
import os
import subprocess

# Fix Unicode encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Import project selector and main GUI
    from gui.ProjectSelector import ProjectSelector
    from gui.app import ModernPenTestSuite
    
    if __name__ == "__main__":
        print("🔒 Starting PenTest MultiTools...")
        print("🎓 Educational Cybersecurity Testing Suite")
        print("=" * 50)
        
        # Show project selector first
        print("📁 Loading project selector...")
        selector = ProjectSelector()
        selector.mainloop()
        
        # Get selected project
        selected_project = selector.get_selected_project()
        
        if selected_project:
            print(f"✅ Project selected: {selected_project['name']}")
            print("🚀 Launching main application...")
            
            # Save selected project ID to temp file for main app to read
            import tempfile
            import json
            temp_file = os.path.join(tempfile.gettempdir(), 'pentest_selected_project.json')
            with open(temp_file, 'w') as f:
                json.dump(selected_project, f)
            
            # Launch main app in new process
            main_app_script = os.path.join(os.path.dirname(__file__), 'gui', 'app.py')
            subprocess.run([sys.executable, main_app_script])
            
        else:
            print("❌ No project selected. Exiting...")
            sys.exit(0)
        
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("💡 Please ensure all dependencies are installed:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting application: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)