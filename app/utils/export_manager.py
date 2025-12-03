"""
Export Manager Utility
Centralized export path management for project-based exports
"""

import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List


class ExportManager:
    """Manages export paths and tracking for project-based exports"""
    
    def __init__(self, project_manager=None):
        """
        Initialize the export manager
        
        Args:
            project_manager: ProjectManager instance (optional)
        """
        self.project_manager = project_manager
        self.current_project_id = None
    
    def set_current_project(self, project_id: str):
        """Set the current active project"""
        self.current_project_id = project_id
    
    def get_project_export_dir(self, project_id: str = None, subdir: str = None) -> Path:
        """
        Get the export directory for a project
        
        Args:
            project_id: Project identifier (uses current if None)
            subdir: Subdirectory name (scans, reports, exports)
            
        Returns:
            Path to export directory
        """
        if project_id is None:
            project_id = self.current_project_id
        
        if project_id is None:
            raise ValueError("No project ID specified and no current project set")
        
        # Get project base directory
        if self.project_manager:
            base_dir = self.project_manager.get_project_path(project_id)
        else:
            # Fallback to default location
            app_dir = Path(__file__).parent.parent
            base_dir = app_dir / "data" / "projects" / project_id
        
        # Get subdirectory
        if subdir:
            export_dir = base_dir / subdir
        else:
            export_dir = base_dir / "exports"
        
        # Create directory if it doesn't exist
        export_dir.mkdir(parents=True, exist_ok=True)
        
        return export_dir
    
    def generate_filename(self, base_name: str, extension: str, 
                         project_id: str = None, include_timestamp: bool = True) -> str:
        """
        Generate a unique filename for export
        
        Args:
            base_name: Base name for the file
            extension: File extension (without dot)
            project_id: Project identifier
            include_timestamp: Whether to include timestamp
            
        Returns:
            Generated filename
        """
        if include_timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{base_name}_{timestamp}.{extension}"
        else:
            filename = f"{base_name}.{extension}"
        
        return filename
    
    def get_scan_export_path(self, base_name: str, extension: str = "json",
                            project_id: str = None) -> Path:
        """
        Get full path for scan export
        
        Args:
            base_name: Base name for the file
            extension: File extension
            project_id: Project identifier
            
        Returns:
            Full path for export file
        """
        export_dir = self.get_project_export_dir(project_id, "scans")
        filename = self.generate_filename(base_name, extension, project_id)
        return export_dir / filename
    
    def get_report_export_path(self, base_name: str, extension: str = "html",
                               project_id: str = None) -> Path:
        """
        Get full path for report export
        
        Args:
            base_name: Base name for the file
            extension: File extension
            project_id: Project identifier
            
        Returns:
            Full path for export file
        """
        export_dir = self.get_project_export_dir(project_id, "reports")
        filename = self.generate_filename(base_name, extension, project_id)
        return export_dir / filename
    
    def get_general_export_path(self, base_name: str, extension: str,
                               project_id: str = None) -> Path:
        """
        Get full path for general export
        
        Args:
            base_name: Base name for the file
            extension: File extension
            project_id: Project identifier
            
        Returns:
            Full path for export file
        """
        export_dir = self.get_project_export_dir(project_id, "exports")
        filename = self.generate_filename(base_name, extension, project_id)
        return export_dir / filename
    
    def get_export_stats(self, project_id: str = None) -> Dict[str, int]:
        """
        Get export statistics for a project
        
        Args:
            project_id: Project identifier
            
        Returns:
            Dictionary with file counts by type
        """
        if project_id is None:
            project_id = self.current_project_id
        
        if project_id is None:
            return {"scans": 0, "reports": 0, "exports": 0, "total": 0}
        
        stats = {"scans": 0, "reports": 0, "exports": 0, "total": 0}
        
        try:
            # Count files in each directory
            for subdir in ["scans", "reports", "exports"]:
                try:
                    export_dir = self.get_project_export_dir(project_id, subdir)
                    if export_dir.exists():
                        # Count only files, not directories
                        file_count = len([f for f in export_dir.iterdir() if f.is_file()])
                        stats[subdir] = file_count
                        stats["total"] += file_count
                except Exception as e:
                    print(f"Error counting files in {subdir}: {e}")
        except Exception as e:
            print(f"Error getting export stats: {e}")
        
        return stats
    
    def list_exports(self, project_id: str = None, subdir: str = None) -> List[Path]:
        """
        List all export files for a project
        
        Args:
            project_id: Project identifier
            subdir: Specific subdirectory to list (None for all)
            
        Returns:
            List of file paths
        """
        if project_id is None:
            project_id = self.current_project_id
        
        if project_id is None:
            return []
        
        files = []
        
        try:
            if subdir:
                subdirs = [subdir]
            else:
                subdirs = ["scans", "reports", "exports"]
            
            for subdir_name in subdirs:
                try:
                    export_dir = self.get_project_export_dir(project_id, subdir_name)
                    if export_dir.exists():
                        files.extend([f for f in export_dir.iterdir() if f.is_file()])
                except Exception as e:
                    print(f"Error listing files in {subdir_name}: {e}")
        except Exception as e:
            print(f"Error listing exports: {e}")
        
        return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)
    
    def open_project_folder(self, project_id: str = None):
        """
        Open project folder in file explorer
        
        Args:
            project_id: Project identifier
        """
        if project_id is None:
            project_id = self.current_project_id
        
        if project_id is None:
            raise ValueError("No project ID specified")
        
        if self.project_manager:
            project_path = self.project_manager.get_project_path(project_id)
        else:
            app_dir = Path(__file__).parent.parent
            project_path = app_dir / "data" / "projects" / project_id
        
        # Open in file explorer
        import subprocess
        import sys
        
        if sys.platform == 'win32':
            os.startfile(str(project_path))
        elif sys.platform == 'darwin':  # macOS
            subprocess.run(['open', str(project_path)])
        else:  # Linux
            subprocess.run(['xdg-open', str(project_path)])
    
    def get_initial_dir_for_dialog(self, project_id: str = None, subdir: str = "exports") -> str:
        """
        Get initial directory for file save dialogs
        
        Args:
            project_id: Project identifier
            subdir: Subdirectory to use
            
        Returns:
            Directory path as string
        """
        try:
            export_dir = self.get_project_export_dir(project_id, subdir)
            return str(export_dir)
        except:
            return os.path.expanduser("~")
