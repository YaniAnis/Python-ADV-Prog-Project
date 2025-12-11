"""
Project Selector GUI - Enhanced Version
Modern, beautiful interface for creating and selecting PenTest projects
"""

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from datetime import datetime
import sys
import os
import tkinter.font as tkfont

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.project_manager import ProjectManager


class ProjectSelector(tb.Window):
    """Modern project selection and creation interface with enhanced design"""
    
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("🔒 PenTest MultiTools - Project Selector")
        self.geometry("1000x700")
        self.resizable(True, True)
        
        # Set minimum size
        self.minsize(800, 600)
        
        # Initialize project manager and export manager
        self.project_manager = ProjectManager()
        try:
            from utils import ExportManager
            self.export_manager = ExportManager(self.project_manager)
        except ImportError:
            self.export_manager = None
            print("Warning: ExportManager could not be imported")

        self.selected_project = None
        self.modern_font = "Arial"
        self._ui_ready = False  # Flag to prevent premature filter calls
        
        # Create UI
        self.setup_styles()
        self.create_ui()
        self.center_window()
        self._ui_ready = True  # UI is now ready
        self.load_projects()
    
    def setup_styles(self):
        """Setup custom styles with enhanced appearance"""
        try:
            available_fonts = tkfont.families()
            modern_fonts = ["Segoe UI", "Arial", "Helvetica", "DejaVu Sans"]
            for font in modern_fonts:
                if font in available_fonts:
                    self.modern_font = font
                    break
        except Exception:
            self.modern_font = "Arial"
        
        # Configure custom styles
        style = tb.Style()
        
        # Custom card style
        style.configure('ProjectCard.TFrame', borderwidth=1, relief='solid', bordercolor='#e0e0e0')
        
        # Header styles
        style.configure('Header.TLabel', font=(self.modern_font, 24, 'bold'))
        style.configure('Subtitle.TLabel', font=(self.modern_font, 11))
        
        # Stat styles
        style.configure('StatValue.TLabel', font=(self.modern_font, 14, 'bold'))
        style.configure('StatLabel.TLabel', font=(self.modern_font, 9))

    def center_window(self):
        """Center window on screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_ui(self):
        """Create the main UI with enhanced design"""
        # Main container
        main_frame = tb.Frame(self, bootstyle="light")
        main_frame.pack(fill=BOTH, expand=True)
        
        # Header
        self.create_header(main_frame)
        
        # Search and filter bar
        self.create_search_bar(main_frame)
        
        # Content area
        content_frame = tb.Frame(main_frame)
        content_frame.pack(fill=BOTH, expand=True, padx=40, pady=(10, 20))
        
        # Projects list frame
        self.create_projects_section(content_frame)
        
        # Footer
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Create enhanced header section"""
        # Header container with primary color background
        header_container = tb.Frame(parent, bootstyle="primary")
        header_container.pack(fill=X)
        
        header_frame = tb.Frame(header_container, bootstyle="primary")
        header_frame.pack(fill=X, padx=40, pady=30)
        
        # Top row: Icon + Title + Stats
        top_row = tb.Frame(header_frame, bootstyle="primary")
        top_row.pack(fill=X)
        
        # Left side: Icon and Title
        title_section = tb.Frame(top_row, bootstyle="primary")
        title_section.pack(side=LEFT)
        
        # Large icon
        icon_label = tb.Label(
            title_section,
            text="🔒",
            font=(self.modern_font, 40),
            bootstyle="inverse-primary"
        )
        icon_label.pack(side=LEFT, padx=(0, 20))
        
        # Title and subtitle
        text_frame = tb.Frame(title_section, bootstyle="primary")
        text_frame.pack(side=LEFT)
        
        title_label = tb.Label(
            text_frame,
            text="PenTest MultiTools",
            font=(self.modern_font, 28, "bold"),
            bootstyle="inverse-primary"
        )
        title_label.pack(anchor=W)
        
        subtitle_label = tb.Label(
            text_frame,
            text="Project Management System",
            font=(self.modern_font, 12),
            bootstyle="inverse-primary"
        )
        subtitle_label.pack(anchor=W, pady=(5, 0))
        
        # Right side: Global Stats
        self.create_header_stats(top_row)

    def create_header_stats(self, parent):
        """Create statistics display in header"""
        stats_frame = tb.Frame(parent, bootstyle="primary")
        stats_frame.pack(side=RIGHT)
        
        # Get project count
        try:
            projects = self.project_manager.list_projects()
            project_count = len(projects)
            total_scans = sum(p.get('stats', {}).get('scans_performed', 0) for p in projects)
        except:
            project_count = 0
            total_scans = 0
        
        # Helper to create a stat box
        def create_stat_box(icon, label, value, color="info"):
            box = tb.Frame(stats_frame, bootstyle=f"{color}", padding=10)
            box.pack(side=LEFT, padx=10)
            
            # Inner layout
            tb.Label(box, text=icon, font=(self.modern_font, 20), bootstyle=f"inverse-{color}").pack(side=LEFT, padx=(0, 10))
            
            txt_frame = tb.Frame(box, bootstyle=f"{color}")
            txt_frame.pack(side=LEFT)
            
            tb.Label(txt_frame, text=value, font=(self.modern_font, 14, "bold"), bootstyle=f"inverse-{color}").pack(anchor=W)
            tb.Label(txt_frame, text=label, font=(self.modern_font, 8), bootstyle=f"inverse-{color}").pack(anchor=W)

        create_stat_box("📁", "Projects", str(project_count), "info")
        create_stat_box("🔍", "Total Scans", str(total_scans), "success")

    def create_search_bar(self, parent):
        """Create search and filter bar"""
        search_frame = tb.Frame(parent)
        search_frame.pack(fill=X, padx=40, pady=(20, 0))
        
        # Search entry container
        search_container = tb.Frame(search_frame)
        search_container.pack(side=LEFT, fill=X, expand=True)
        
        tb.Label(search_container, text="🔍", font=(self.modern_font, 14)).pack(side=LEFT, padx=(0, 10))
        
        self.search_var = tb.StringVar()
        search_entry = tb.Entry(
            search_container,
            textvariable=self.search_var,
            font=(self.modern_font, 11),
            width=40
        )
        search_entry.pack(side=LEFT, fill=X, expand=True)
        
        # Bind search
        self.after(100, lambda: self.search_var.trace('w', lambda *args: self.filter_projects()))
        
        # Placeholder logic
        search_entry.insert(0, "Search projects...")
        search_entry.config(foreground="gray")
        
        def on_focus_in(event):
            if search_entry.get() == "Search projects...":
                search_entry.delete(0, "end")
                search_entry.config(foreground="black")
        
        def on_focus_out(event):
            if not search_entry.get():
                search_entry.insert(0, "Search projects...")
                search_entry.config(foreground="gray")
        
        search_entry.bind("<FocusIn>", on_focus_in)
        search_entry.bind("<FocusOut>", on_focus_out)
        
        # Sort options
        sort_frame = tb.Frame(search_frame)
        sort_frame.pack(side=RIGHT, padx=(20, 0))
        
        tb.Label(sort_frame, text="Sort by:", font=(self.modern_font, 9), bootstyle="secondary").pack(side=LEFT, padx=(0, 5))
        
        self.sort_var = tb.StringVar(value="Recent")
        sort_menu = tb.Combobox(
            sort_frame,
            textvariable=self.sort_var,
            values=["Recent", "Name", "Oldest", "Most Scans"],
            state="readonly",
            width=12,
            font=(self.modern_font, 9)
        )
        sort_menu.pack(side=LEFT)
        sort_menu.bind("<<ComboboxSelected>>", lambda e: self.load_projects())
    
    def create_projects_section(self, parent):
        """Create scrollable projects list section"""
        # Container
        container = tb.Frame(parent)
        container.pack(fill=BOTH, expand=True)
        
        # Canvas and Scrollbar
        canvas = tb.Canvas(container, highlightthickness=0, bg=self.cget('background'))
        scrollbar = tb.Scrollbar(container, orient=VERTICAL, command=canvas.yview, bootstyle="primary-round")
        
        self.projects_frame = tb.Frame(canvas)
        self.projects_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.projects_frame, anchor=NW, width=canvas.winfo_reqwidth())
        
        # Update canvas window width on resize
        def on_canvas_configure(event):
            canvas.itemconfig(canvas.find_withtag("all")[0], width=event.width)
        
        canvas.bind("<Configure>", on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Mousewheel scrolling
        self.canvas = canvas
        self.bind_mousewheel()
    
    def bind_mousewheel(self):
        def on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.canvas.bind_all("<MouseWheel>", on_mousewheel)

    def create_footer(self, parent):
        """Create footer with main actions"""
        footer_frame = tb.Frame(parent)
        footer_frame.pack(fill=X, side=BOTTOM, padx=40, pady=(0, 25))
        
        tb.Separator(footer_frame, orient=HORIZONTAL).pack(fill=X, pady=(0, 20))
        
        # Buttons
        buttons_frame = tb.Frame(footer_frame)
        buttons_frame.pack(fill=X)
        
        # Create New Project
        tb.Button(
            buttons_frame,
            text="➕ Create New Project",
            bootstyle="success",
            command=self.create_new_project,
            width=25
        ).pack(side=LEFT, padx=(0, 10))
        
        # Refresh
        tb.Button(
            buttons_frame,
            text="🔄 Refresh",
            bootstyle="info-outline",
            command=self.load_projects,
            width=12
        ).pack(side=LEFT)
        
        # Exit
        tb.Button(
            buttons_frame,
            text="❌ Exit",
            bootstyle="danger-outline",
            command=self.exit_application,
            width=10
        ).pack(side=RIGHT)

    def load_projects(self):
        """Load and display projects"""
        # Clear existing
        for widget in self.projects_frame.winfo_children():
            widget.destroy()
            
        projects = self.project_manager.list_projects()
        
        # Filter
        if self._ui_ready:
            search_text = self.search_var.get().lower()
            if search_text and search_text != "search projects...":
                projects = [p for p in projects if search_text in p['name'].lower() or 
                           (p.get('description') and search_text in p['description'].lower())]
        
        # Sort
        sort_by = self.sort_var.get()
        if sort_by == "Name":
            projects.sort(key=lambda x: x['name'].lower())
        elif sort_by == "Oldest":
            projects.sort(key=lambda x: x['created_at'])
        elif sort_by == "Most Scans":
            projects.sort(key=lambda x: x.get('stats', {}).get('scans_performed', 0), reverse=True)
        else: # Recent
            projects.sort(key=lambda x: x['modified_at'], reverse=True)
            
        if not projects:
            self.show_empty_state()
            return
            
        # Grid layout
        columns = 2
        for i, project in enumerate(projects):
            row = i // columns
            col = i % columns
            
            card = self.create_project_card(self.projects_frame, project, i)
            card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
            
        # Configure grid columns
        for i in range(columns):
            self.projects_frame.columnconfigure(i, weight=1)

    def show_empty_state(self):
        """Show empty state message"""
        frame = tb.Frame(self.projects_frame)
        frame.pack(fill=BOTH, expand=True, pady=50)
        
        tb.Label(frame, text="📭", font=(self.modern_font, 48)).pack()
        tb.Label(frame, text="No projects found", font=(self.modern_font, 16, "bold")).pack(pady=10)
        tb.Label(frame, text="Create a new project to get started", font=(self.modern_font, 11), bootstyle="secondary").pack()

    def create_project_card(self, parent, project, index):
        """Create an enhanced project card"""
        card_container = tb.Frame(parent)
        
        # Card Frame
        card = tb.Labelframe(
            card_container,
            text=f" {project['name']} ",
            padding=15,
            bootstyle="primary" if index == 0 else "default"
        )
        card.pack(fill=BOTH, expand=True)
        
        # Description
        desc = project.get('description', 'No description')
        if len(desc) > 80: desc = desc[:77] + "..."
        tb.Label(card, text=desc, bootstyle="secondary", wraplength=300).pack(fill=X, pady=(0, 10))
        
        # Stats Grid
        stats_frame = tb.Frame(card)
        stats_frame.pack(fill=X, pady=(0, 15))
        
        # Get export stats if available
        total_files = 0
        scans_files = 0
        reports_files = 0
        other_files = 0
        
        if self.export_manager:
            try:
                estats = self.export_manager.get_export_stats(project['id'])
                total_files = estats.get('total', 0)
                scans_files = estats.get('scans', 0)
                reports_files = estats.get('reports', 0)
                other_files = estats.get('exports', 0)
            except Exception:
                pass

        # Row 1: Dates
        r1 = tb.Frame(stats_frame)
        r1.pack(fill=X, pady=2)
        tb.Label(r1, text=f"📅 Created: {self.format_date(project['created_at'])}", font=(self.modern_font, 8)).pack(side=LEFT)
        tb.Label(r1, text=f"🕒 Modified: {self.format_date(project['modified_at'])}", font=(self.modern_font, 8)).pack(side=RIGHT)
        
        # Row 2: Counts
        r2 = tb.Frame(stats_frame)
        r2.pack(fill=X, pady=5)
        
        scans_count = project.get('stats', {}).get('scans_performed', 0)
        
        # Scans badge
        b1 = tb.Label(r2, text=f"🔍 Scans: {scans_count}", bootstyle="inverse-info", font=(self.modern_font, 9))
        b1.pack(side=LEFT, padx=(0, 5))
        
        # Files badge
        b2 = tb.Label(r2, text=f"📁 Files: {total_files}", bootstyle="inverse-secondary", font=(self.modern_font, 9))
        b2.pack(side=LEFT)
        
        # Detailed file stats
        if total_files > 0:
            r3 = tb.Frame(stats_frame)
            r3.pack(fill=X, pady=(2, 0))
            detail_text = f"📊 Scans: {scans_files} | Reports: {reports_files} | Other: {other_files}"
            tb.Label(r3, text=detail_text, font=(self.modern_font, 7), bootstyle="secondary").pack(anchor=W)

        # Buttons
        btn_frame = tb.Frame(card)
        btn_frame.pack(fill=X, pady=(5, 0))
        
        # Open Project
        tb.Button(
            btn_frame,
            text="🚀 Open",
            bootstyle="success" if index == 0 else "primary",
            command=lambda p=project: self.open_project(p),
            width=10
        ).pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
        
        # Open Folder
        tb.Button(
            btn_frame,
            text="📂",
            bootstyle="info-outline",
            command=lambda p=project: self.open_project_folder(p),
            width=4
        ).pack(side=LEFT, padx=(0, 5))
        
        # Delete
        tb.Button(
            btn_frame,
            text="🗑️",
            bootstyle="danger-outline",
            command=lambda p=project: self.delete_project(p),
            width=4
        ).pack(side=LEFT)
        
        return card_container

    def format_date(self, date_str):
        """Format date to relative time"""
        if not date_str: return "Unknown"
        try:
            dt = datetime.fromisoformat(date_str)
            now = datetime.now()
            diff = now - dt
            
            if diff.days == 0:
                if diff.seconds < 60: return "Just now"
                if diff.seconds < 3600: return f"{diff.seconds // 60}m ago"
                return f"{diff.seconds // 3600}h ago"
            if diff.days == 1: return "Yesterday"
            if diff.days < 7: return f"{diff.days}d ago"
            return dt.strftime("%Y-%m-%d")
        except:
            return date_str

    def filter_projects(self, *args):
        if self._ui_ready:
            self.load_projects()

    def create_new_project(self):
        """Show dialog to create new project"""
        d = tb.Toplevel(self)
        d.title("Create New Project")
        d.geometry("500x350")
        d.resizable(False, False)
        
        # Center dialog
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 250
        y = self.winfo_y() + (self.winfo_height() // 2) - 175
        d.geometry(f"+{x}+{y}")
        
        # Content
        content = tb.Frame(d, padding=20)
        content.pack(fill=BOTH, expand=True)
        
        tb.Label(content, text="New Project Details", font=(self.modern_font, 16, "bold")).pack(pady=(0, 20))
        
        # Name
        tb.Label(content, text="Project Name *").pack(anchor=W)
        name_var = tb.StringVar()
        name_entry = tb.Entry(content, textvariable=name_var)
        name_entry.pack(fill=X, pady=(5, 15))
        name_entry.focus()
        
        # Description
        tb.Label(content, text="Description (Optional)").pack(anchor=W)
        desc_text = tb.Text(content, height=3, width=40)
        desc_text.pack(fill=X, pady=(5, 20))
        
        # Buttons
        btn_frame = tb.Frame(content)
        btn_frame.pack(fill=X)
        
        def save():
            name = name_var.get().strip()
            if not name:
                tb.dialogs.Messagebox.show_error("Project name is required", "Validation Error", parent=d)
                return
            
            desc = desc_text.get("1.0", "end-1c").strip()
            try:
                self.project_manager.create_project(name, desc)
                d.destroy()
                self.load_projects()
                tb.dialogs.Messagebox.show_info(f"Project '{name}' created successfully!", "Success", parent=self)
            except ValueError as e:
                tb.dialogs.Messagebox.show_error(str(e), "Error", parent=d)
            except Exception as e:
                tb.dialogs.Messagebox.show_error(f"Failed to create project: {e}", "Error", parent=d)

        tb.Button(btn_frame, text="Create Project", bootstyle="success", command=save).pack(side=RIGHT)
        tb.Button(btn_frame, text="Cancel", bootstyle="secondary-outline", command=d.destroy).pack(side=RIGHT, padx=10)

    def open_project(self, project):
        """Open the selected project"""
        self.selected_project = project
        self.project_manager.update_project_stats(project['id'], {'last_accessed': datetime.now().isoformat()})
        self.destroy()

    def open_project_folder(self, project):
        """Open project folder in file explorer"""
        if self.export_manager:
            try:
                self.export_manager.open_project_folder(project['id'])
            except Exception as e:
                tb.dialogs.Messagebox.show_error(f"Could not open folder: {e}", "Error", parent=self)
        else:
            tb.dialogs.Messagebox.show_error("Export Manager not available", "Error", parent=self)

    def delete_project(self, project):
        """Delete a project"""
        confirm = tb.dialogs.Messagebox.show_question(
            f"Are you sure you want to delete '{project['name']}'?\nThis action cannot be undone and will delete all associated files.",
            "Confirm Deletion",
            buttons=["No:secondary", "Yes:danger"],
            parent=self
        )
        
        if confirm == "Yes":
            try:
                self.project_manager.delete_project(project['id'])
                self.load_projects()
                tb.dialogs.Messagebox.show_info(f"Project '{project['name']}' deleted.", "Deleted", parent=self)
            except Exception as e:
                tb.dialogs.Messagebox.show_error(f"Failed to delete project: {e}", "Error", parent=self)

    def show_help(self):
        """Show help dialog"""
        msg = """
        🔒 PenTest MultiTools Project Manager
        
        • Create projects to organize your work
        • All scans and reports are saved to the project folder
        • Use the 📂 button to quickly access files
        • Search and sort to find projects easily
        """
        tb.dialogs.Messagebox.show_info(msg, "Help", parent=self)

    def exit_application(self):
        """Exit the application"""
        self.selected_project = None
        self.destroy()
        sys.exit(0)

    def get_selected_project(self):
        return self.selected_project


if __name__ == "__main__":
    app = ProjectSelector()
    app.mainloop()
