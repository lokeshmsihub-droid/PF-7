import os
from typing import Dict, List, Set, Any
from app.schemas.scan import RepositoryMetadata

DEFAULT_EXCLUDED_DIRS = {
    ".git": "git metadata",
    "node_modules": "dependency directory",
    ".next": "generated build",
    "dist": "build output",
    "build": "build output",
    "coverage": "test coverage reports",
    "vendor": "vendored dependencies",
    ".venv": "python virtual environment",
    "venv": "python virtual environment",
    "__pycache__": "compiled python bytecode",
    ".turbo": "build cache",
    ".cache": "temporary cache",
    ".idea": "IDE configuration",
    ".vscode": "IDE configuration",
    "bin": "binary directory",
    "obj": "intermediate build objects",
    "target": "compiler target directory"
}

BINARY_EXTENSIONS = {
    ".png": "binary image",
    ".jpg": "binary image",
    ".jpeg": "binary image",
    ".gif": "binary image",
    ".ico": "binary icon",
    ".pdf": "document binary",
    ".zip": "archive",
    ".tar": "archive",
    ".gz": "archive",
    ".exe": "executable binary",
    ".dll": "shared library binary",
    ".so": "shared library binary",
    ".dylib": "mach-o binary",
    ".class": "java bytecode",
    ".jar": "java archive",
    ".pyc": "python bytecode",
    ".woff": "font binary",
    ".woff2": "font binary",
    ".ttf": "font binary",
    ".eot": "font binary",
    ".mp4": "video media",
    ".mov": "video media",
    ".bin": "generic binary"
}

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".ipynb": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".scala": "scala",
    ".swift": "swift",
    ".dart": "dart",
    ".lua": "lua",
    ".r": "r",
    ".pl": "perl",
    ".pm": "perl",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".bat": "batch",
    ".ps1": "powershell",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".hcl": "hcl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".ini": "ini",
    ".cfg": "config",
    ".conf": "config",
    ".properties": "properties",
    ".env": "dotenv",
    ".dockerfile": "dockerfile",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    ".vue": "vue",
    ".svelte": "svelte",
    ".graphql": "graphql",
    ".proto": "protobuf",
    ".sql": "sql",
    ".md": "markdown",
    ".txt": "text",
    ".csv": "csv"
}

FRAMEWORK_INDICATORS = {
    "package.json": {
        "react": "React",
        "next": "Next.js",
        "vue": "Vue.js",
        "express": "Express",
        "@angular/core": "Angular",
        "nestjs": "NestJS"
    },
    "requirements.txt": {
        "fastapi": "FastAPI",
        "django": "Django",
        "flask": "Flask",
        "tornado": "Tornado"
    },
    "pom.xml": {
        "spring-boot": "Spring Boot"
    },
    "go.mod": {
        "gin-gonic": "Gin",
        "gorilla/mux": "Gorilla",
        "echo": "Echo"
    }
}

PACKAGE_MANAGERS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Pipfile": "pipenv",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "requirements.txt": "pip",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "Cargo.lock": "cargo",
    "go.mod": "go-modules",
    "Gemfile.lock": "bundler",
    "composer.json": "composer"
}

class RepositoryAnalyzer:
    """
    Analyzes repository workspace to detect languages, frameworks, package managers,
    and configurations while tracking exact coverage and reasons for exclusions.
    """

    def analyze(self, workspace_path: str) -> RepositoryMetadata:
        languages_detected: Set[str] = set()
        frameworks_detected: Set[str] = set()
        package_managers_detected: Set[str] = set()
        config_files_detected: Set[str] = set()
        relevant_extensions: Set[str] = set()
        
        files_discovered = 0
        files_scanned = 0
        files_excluded = 0
        files_failed = 0
        
        exclusion_reasons: Dict[str, str] = {}
        ignored_dirs: Set[str] = set()
        
        total_size = 0
        
        for root, dirs, files in os.walk(workspace_path):
            # Check excluded directories
            original_dirs = list(dirs)
            for d in original_dirs:
                if d in DEFAULT_EXCLUDED_DIRS:
                    reason = DEFAULT_EXCLUDED_DIRS[d]
                    rel_dir = os.path.relpath(os.path.join(root, d), workspace_path)
                    exclusion_reasons[rel_dir] = reason
                    ignored_dirs.add(d)
            
            # Prune directory tree walk
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS]
            
            for file_name in files:
                files_discovered += 1
                full_path = os.path.join(root, file_name)
                rel_file = os.path.relpath(full_path, workspace_path)
                ext = os.path.splitext(file_name)[1].lower()
                
                # Check binary exclusion
                if ext in BINARY_EXTENSIONS:
                    files_excluded += 1
                    exclusion_reasons[rel_file] = BINARY_EXTENSIONS[ext]
                    continue
                    
                try:
                    file_size = os.path.getsize(full_path)
                except OSError:
                    files_failed += 1
                    exclusion_reasons[rel_file] = "filesystem access error"
                    continue
                    
                # Skip files larger than 5MB
                if file_size > 5 * 1024 * 1024:
                    files_excluded += 1
                    exclusion_reasons[rel_file] = "size limit (>5MB)"
                    continue
                    
                total_size += file_size

                # Check Package Managers & Config Files
                if file_name in PACKAGE_MANAGERS:
                    package_managers_detected.add(PACKAGE_MANAGERS[file_name])
                    config_files_detected.add(file_name)
                    
                # Check Framework Indicators
                if file_name in FRAMEWORK_INDICATORS:
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(50000)
                            for indicator, framework_name in FRAMEWORK_INDICATORS[file_name].items():
                                if indicator.lower() in content.lower():
                                    frameworks_detected.add(framework_name)
                    except Exception:
                        pass
                        
                if file_name in (".env.example", "tsconfig.json", "dune-project", "tox.ini", "pytest.ini"):
                    config_files_detected.add(file_name)

                # Supported source file or scannable text/config file
                if ext in EXTENSION_TO_LANGUAGE:
                    lang = EXTENSION_TO_LANGUAGE[ext]
                    languages_detected.add(lang)
                    relevant_extensions.add(ext)
                    files_scanned += 1
                elif file_name.lower() in ("dockerfile", "makefile", "procfile", "license", "gemfile", "readme"):
                    languages_detected.add(file_name.lower())
                    files_scanned += 1
                else:
                    # Non-binary file included in scan scope (secrets, config, data audit)
                    files_scanned += 1
                    if ext:
                        relevant_extensions.add(ext)

        # Calculate coverage percentage
        coverage_pct = round((files_scanned / max(files_discovered, 1)) * 100, 1)

        return RepositoryMetadata(
            repository_path=workspace_path,
            languages=sorted(list(languages_detected)),
            frameworks=sorted(list(frameworks_detected)),
            package_managers=sorted(list(package_managers_detected)),
            config_files=sorted(list(config_files_detected)),
            total_size_bytes=total_size,
            total_files=files_scanned,
            files_discovered=files_discovered,
            files_scanned=files_scanned,
            files_excluded=files_excluded,
            files_failed=files_failed,
            coverage_percentage=coverage_pct,
            exclusion_reasons=exclusion_reasons,
            ignored_directories=sorted(list(ignored_dirs)),
            relevant_extensions=sorted(list(relevant_extensions))
        )

    def build_profile(
        self,
        workspace_path: str,
        repository_id: str,
        commit_sha: str,
        repository_name: Optional[str] = None
    ) -> Any:
        from app.schemas.scan import RepositoryProfile

        meta = self.analyze(workspace_path)
        source_targets = []
        dependency_targets = []
        iac_targets = []
        container_targets = []
        manifests = []

        for root, dirs, files in os.walk(workspace_path):
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), workspace_path)
                ext = os.path.splitext(f)[1].lower()
                fname_lower = f.lower()

                if ext in EXTENSION_TO_LANGUAGE and ext not in [".yaml", ".yml", ".json", ".tf"]:
                    if len(source_targets) < 50:
                        source_targets.append(rel)
                
                if f in PACKAGE_MANAGERS:
                    dependency_targets.append(rel)
                    manifests.append(rel)
                
                if ext in [".tf"] or fname_lower in ["dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
                    iac_targets.append(rel)
                elif ext in [".yaml", ".yml"] and any(k in rel.lower() for k in ["k8s", "deploy", "helm", "cloudformation", "terraform"]):
                    iac_targets.append(rel)

                if fname_lower in ["dockerfile", "containerfile"] or fname_lower.endswith(".dockerfile"):
                    container_targets.append(rel)

        return RepositoryProfile(
            repository_id=repository_id,
            repository_name=repository_name,
            commit_sha=commit_sha,
            languages=meta.languages,
            frameworks=meta.frameworks,
            package_managers=meta.package_managers,
            source_targets=source_targets,
            dependency_targets=dependency_targets,
            iac_targets=iac_targets,
            container_targets=container_targets,
            manifests=manifests,
            files_discovered=meta.files_discovered,
            files_scannable=meta.files_scanned,
            files_excluded=meta.files_excluded,
            coverage_percentage=meta.coverage_percentage
        )

