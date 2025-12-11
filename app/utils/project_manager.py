"""
Project Manager Utility
Handles project creation, loading, saving, and management for PenTest MultiTools
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ProjectManager:
    """Manages penetration testing projects with persistence"""
    
    def __init__(self, projects_dir: str = None):
        """
        Initialize the project manager
        
        Args:
            projects_dir: Directory to store project files (default: app/data/projects)
        """
        if projects_dir is None:
            # Get the app directory (parent of utils)
            app_dir = Path(__file__).parent.parent
            projects_dir = app_dir / "data" / "projects"
        
        self.projects_dir = Path(projects_dir)
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.current_project = None
    
    def create_project(self, name: str, description: str = "") -> Dict:
        """
        Create a new project
        
        Args:
            name: Project name
            description: Optional project description
            
        Returns:
            Project metadata dictionary
            
        Raises:
            ValueError: If project name already exists or is invalid
        """
        # Validate project name
        if not name or not name.strip():
            raise ValueError("Project name cannot be empty")
        
        # Sanitize name for filesystem
        safe_name = self._sanitize_filename(name)
        project_path = self.projects_dir / safe_name
        
        if project_path.exists():
            raise ValueError(f"Project '{name}' already exists")
        
        # Create project directory
        project_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (project_path / "reports").mkdir(exist_ok=True)
        (project_path / "scans").mkdir(exist_ok=True)
        (project_path / "exports").mkdir(exist_ok=True)
        
        # Create project metadata
        now = datetime.now().isoformat()
        project_data = {
            "id": safe_name,
            "name": name,
            "description": description,
            "created_at": now,
            "modified_at": now,
            "settings": {
                "auto_save": True,
                "theme": "cosmo"
            },
            "stats": {
                "scans_performed": 0,
                "reports_generated": 0,
                "last_scan": None
            }
        }
        
        # Save metadata
        self._save_project_metadata(safe_name, project_data)
        
        return project_data
    
    def load_project(self, project_id: str) -> Dict:
        """
        Load a project by ID
        
        Args:
            project_id: Project identifier (safe filename)
            
        Returns:
            Project metadata dictionary
            
        Raises:
            FileNotFoundError: If project doesn't exist
        """
        project_path = self.projects_dir / project_id
        
        if not project_path.exists():
            raise FileNotFoundError(f"Project '{project_id}' not found")
        
        metadata_file = project_path / "project.json"
        
        if not metadata_file.exists():
            raise FileNotFoundError(f"Project metadata not found for '{project_id}'")
        
        with open(metadata_file, 'r', encoding='utf-8') as f:
            project_data = json.load(f)
        
        self.current_project = project_data
        return project_data
    
    def list_projects(self) -> List[Dict]:
        """
        List all available projects
        
        Returns:
            List of project metadata dictionaries
        """
        projects = []
        
        if not self.projects_dir.exists():
            return projects
        
        for project_dir in self.projects_dir.iterdir():
            if project_dir.is_dir():
                metadata_file = project_dir / "project.json"
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r', encoding='utf-8') as f:
                            project_data = json.load(f)
                            projects.append(project_data)
                    except (json.JSONDecodeError, IOError) as e:
                        print(f"Error loading project {project_dir.name}: {e}")
        
        # Sort by modified date (most recent first)
        projects.sort(key=lambda p: p.get('modified_at', ''), reverse=True)
        
        return projects
    
    def delete_project(self, project_id: str) -> bool:
        """
        Delete a project
        
        Args:
            project_id: Project identifier
            
        Returns:
            True if deleted successfully
            
        Raises:
            FileNotFoundError: If project doesn't exist
        """
        project_path = self.projects_dir / project_id
        
        if not project_path.exists():
            raise FileNotFoundError(f"Project '{project_id}' not found")
        
        # Remove all files and directories
        import shutil
        shutil.rmtree(project_path)
        
        # Clear current project if it was deleted
        if self.current_project and self.current_project.get('id') == project_id:
            self.current_project = None
        
        return True
    
    def update_project(self, project_id: str, updates: Dict) -> Dict:
        """
        Update project metadata
        
        Args:
            project_id: Project identifier
            updates: Dictionary of fields to update
            
        Returns:
            Updated project metadata
        """
        project_data = self.load_project(project_id)
        
        # Update fields
        for key, value in updates.items():
            if key not in ['id', 'created_at']:  # Don't allow changing these
                project_data[key] = value
        
        # Update modification time
        project_data['modified_at'] = datetime.now().isoformat()
        
        # Save updated metadata
        self._save_project_metadata(project_id, project_data)
        
        return project_data
    
    def get_current_project(self) -> Optional[Dict]:
        """Get the currently active project"""
        return self.current_project
    
    def set_current_project(self, project_id: str) -> Dict:
        """
        Set the current active project
        
        Args:
            project_id: Project identifier
            
        Returns:
            Project metadata
        """
        return self.load_project(project_id)
    
    def increment_scan_count(self, project_id: str = None):
        """Increment the scan count for a project"""
        if project_id is None and self.current_project:
            project_id = self.current_project['id']
        
        if project_id:
            project_data = self.load_project(project_id)
            project_data['stats']['scans_performed'] += 1
            project_data['stats']['last_scan'] = datetime.now().isoformat()
            self._save_project_metadata(project_id, project_data)
    
    def increment_report_count(self, project_id: str = None):
        """Increment the report count for a project"""
        if project_id is None and self.current_project:
            project_id = self.current_project['id']
        
        if project_id:
            project_data = self.load_project(project_id)
            project_data['stats']['reports_generated'] += 1
            self._save_project_metadata(project_id, project_data)

    def update_project_stats(self, project_id: str, stats_updates: Dict):
        """
        Update project statistics
        
        Args:
            project_id: Project identifier
            stats_updates: Dictionary of stats to update
        """
        project_data = self.load_project(project_id)
        
        # Initialize stats if missing
        if 'stats' not in project_data:
            project_data['stats'] = {}
            
        # Update stats
        for key, value in stats_updates.items():
            project_data['stats'][key] = value
            
        self._save_project_metadata(project_id, project_data)
    
    def get_project_path(self, project_id: str) -> Path:
        """Get the filesystem path for a project"""
        return self.projects_dir / project_id
    
    def _save_project_metadata(self, project_id: str, project_data: Dict):
        """Save project metadata to JSON file"""
        project_path = self.projects_dir / project_id
        metadata_file = project_path / "project.json"
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(project_data, f, indent=2, ensure_ascii=False)
    
    def _sanitize_filename(self, name: str) -> str:
        """
        Sanitize a project name for use as a filename
        
        Args:
            name: Original project name
            
        Returns:
            Safe filename string
        """
        # Remove or replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        safe_name = name.strip()
        
        for char in invalid_chars:
            safe_name = safe_name.replace(char, '_')
        
        # Replace spaces with underscores
        safe_name = safe_name.replace(' ', '_')
        
        # Remove multiple consecutive underscores
        while '__' in safe_name:
            safe_name = safe_name.replace('__', '_')
        
        # Limit length
        if len(safe_name) > 50:
            safe_name = safe_name[:50]
        
        # Ensure it's not empty
        if not safe_name:
            safe_name = f"project_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return safe_name
