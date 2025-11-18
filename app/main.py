"""
PenTest MultiTools - Main Application Entry Point
Advanced Cybersecurity Testing Suite for Educational Purposes
"""

import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Import and run the main GUI application
    from gui.app import ModernPenTestSuite
    
    if __name__ == "__main__":
        print("🔒 Starting PenTest MultiTools...")
        print("🎓 Educational Cybersecurity Testing Suite")
        print("=" * 50)
        
        # Launch the modern GUI
        app = ModernPenTestSuite()
        
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("💡 Please ensure all dependencies are installed:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting application: {e}")
    sys.exit(1)