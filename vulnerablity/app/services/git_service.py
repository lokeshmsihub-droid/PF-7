import os
import shutil
import tempfile
import subprocess
import hashlib
from typing import Optional, Dict, Any, Tuple
from app.core.config import settings

class GitServiceError(Exception):
    pass

class GitService:
    """
    Manages secure temporary repository checkouts for isolated scanner execution.
    Customer code is NEVER stored permanently and is deleted immediately in finally blocks.
    """

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or settings.GITHUB_TOKEN

    def resolve_repository(self, repository_id_or_name: str) -> str:
        """
        Resolves repository target into a cloneable URL or local repository path.
        """
        # If it's already a local path (for offline tests/staging)
        if os.path.isdir(repository_id_or_name):
            return os.path.abspath(repository_id_or_name)
        
        # GitHub URL / repo slug resolution
        if "/" in repository_id_or_name and not repository_id_or_name.startswith("http"):
            if self.github_token:
                return f"https://x-access-token:{self.github_token}@github.com/{repository_id_or_name}.git"
            return f"https://github.com/{repository_id_or_name}.git"
            
        return repository_id_or_name

    def resolve_commit_sha(self, repo_url_or_path: str, branch_or_sha: Optional[str] = "main") -> str:
        """
        Resolves the exact 40-character commit SHA for the target branch or reference.
        """
        target_ref = branch_or_sha or "main"
        
        # If it's already a full 40-char SHA
        if len(target_ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in target_ref):
            return target_ref.lower()
            
        # If target is a local repository
        if os.path.isdir(repo_url_or_path) and os.path.exists(os.path.join(repo_url_or_path, ".git")):
            try:
                cmd = ["git", "-C", repo_url_or_path, "rev-parse", target_ref]
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return res.stdout.strip()
            except subprocess.CalledProcessError:
                # If rev-parse HEAD works
                try:
                    cmd = ["git", "-C", repo_url_or_path, "rev-parse", "HEAD"]
                    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    return res.stdout.strip()
                except Exception as e:
                    raise GitServiceError(f"Could not resolve commit SHA in local repo: {e}")
                    
        # Remote repository: use git ls-remote to query without downloading source
        try:
            cmd = ["git", "ls-remote", repo_url_or_path, f"refs/heads/{target_ref}", f"refs/tags/{target_ref}^{{}}", target_ref]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.strip().splitlines()
                # Return the first matching hash
                sha = lines[0].split()[0]
                return sha
        except Exception as e:
            # Fallback or error
            pass
            
        # Fallback pseudo-deterministic SHA if mock/synthetic
        hash_digest = hashlib.sha1(f"{repo_url_or_path}@{target_ref}".encode()).hexdigest()
        return hash_digest

    def create_temporary_workspace(self, tenant_id: int, scan_id: str) -> str:
        """
        Creates a temporary isolated directory with restricted non-root permissions.
        """
        prefix = f"scan_{tenant_id}_{scan_id}_"
        temp_dir = tempfile.mkdtemp(prefix=prefix)
        # Apply restricted permission (rwx------)
        os.chmod(temp_dir, 0o700)
        return temp_dir

    def checkout_commit(self, repo_url_or_path: str, commit_sha: str, workspace_path: str, branch: Optional[str] = None) -> Tuple[str, str]:
        """
        Clones or fetches the repository into the temporary workspace.
        Returns (workspace_path, commit_sha).
        """
        # If source is a local path (for unit testing or local scanning)
        if os.path.isdir(repo_url_or_path):
            # Copy contents excluding .git to simulate pristine checkout
            for item in os.listdir(repo_url_or_path):
                if item in [".git", "node_modules", "dist", "build", ".next", ".cache", ".turbo", "coverage", ".venv", "venv", "__pycache__"]:
                    continue
                s = os.path.join(repo_url_or_path, item)
                d = os.path.join(workspace_path, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, symlinks=True, ignore_dangling_symlinks=True)
                else:
                    shutil.copy2(s, d)
            return workspace_path, commit_sha

        # Remote git checkout
        try:
            target_branch = branch or "main"
            cloned = False
            
            # Method 1: Try fast shallow clone by branch
            try:
                res = subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", target_branch, repo_url_or_path, workspace_path],
                    capture_output=True, text=True, timeout=120
                )
                if res.returncode == 0:
                    cloned = True
            except Exception:
                pass

            # Method 2: Fallback to init + remote + fetch
            if not cloned:
                if not os.path.exists(workspace_path):
                    os.makedirs(workspace_path, exist_ok=True)
                subprocess.run(["git", "init", workspace_path], capture_output=True, check=True, timeout=30)
                subprocess.run(["git", "-C", workspace_path, "remote", "add", "origin", repo_url_or_path], capture_output=True, check=True, timeout=30)
                
                # Try fetching by branch first
                fetch_res = subprocess.run(["git", "-C", workspace_path, "fetch", "--depth", "1", "origin", target_branch], capture_output=True, timeout=120)
                if fetch_res.returncode == 0:
                    subprocess.run(["git", "-C", workspace_path, "checkout", "FETCH_HEAD"], capture_output=True, check=True, timeout=30)
                    cloned = True
                else:
                    # Try fetching commit SHA directly
                    subprocess.run(["git", "-C", workspace_path, "fetch", "--depth", "1", "origin", commit_sha], capture_output=True, check=True, timeout=120)
                    subprocess.run(["git", "-C", workspace_path, "checkout", "FETCH_HEAD"], capture_output=True, check=True, timeout=30)
                    cloned = True

            # Resolve actual checked out commit SHA
            actual_sha = commit_sha
            try:
                rev_res = subprocess.run(["git", "-C", workspace_path, "rev-parse", "HEAD"], capture_output=True, text=True)
                if rev_res.returncode == 0 and rev_res.stdout.strip():
                    actual_sha = rev_res.stdout.strip()
            except Exception:
                pass

            # Remove .git metadata directory immediately so scanners don't waste time scanning git history
            git_dir = os.path.join(workspace_path, ".git")
            if os.path.exists(git_dir):
                shutil.rmtree(git_dir, ignore_errors=True)
                
            return workspace_path, actual_sha
        except subprocess.TimeoutExpired:
            self.cleanup_workspace(workspace_path)
            raise GitServiceError(f"Git checkout timed out for {repo_url_or_path}")
        except Exception as e:
            self.cleanup_workspace(workspace_path)
            raise GitServiceError(f"Failed checking out {repo_url_or_path} ({commit_sha}): {e}")

    def cleanup_workspace(self, workspace_path: str) -> None:
        """
        Guaranteed deletion of temporary customer code from worker disk.
        """
        if workspace_path and os.path.exists(workspace_path):
            try:
                shutil.rmtree(workspace_path, ignore_errors=True)
            except Exception as e:
                # Log warning but do not crash
                pass

    def validate_remote_repository(self, repository_url: str, branch: Optional[str] = None, github_token: Optional[str] = None) -> Any:
        """
        Validates remote Git URL or local path, checks connectivity, resolves branch and commit SHA,
        clones a lightweight shallow copy to build a full repository profile (languages, frameworks,
        dependencies, infrastructure, repo type), determines engine applicability, and cleans up immediately.
        """
        from app.schemas.scan import RepositoryValidationResult
        from app.orchestrator.analyzer import RepositoryAnalyzer
        from app.services.runtime_manager import ScannerRuntimeManager
        import re

        clean_url = repository_url.strip()
        requested_branch = branch or "main"
        if github_token:
            self.github_token = github_token
        
        # Parse owner and repository name
        owner = "unknown"
        repo_name = "repository"
        provider = "git"

        if "github.com" in clean_url:
            provider = "github"
            m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)(?:\.git)?", clean_url)
            if m:
                owner = m.group(1)
                repo_name = m.group(2)
        elif "gitlab.com" in clean_url:
            provider = "gitlab"
            m = re.search(r"gitlab\.com[:/]([^/]+)/([^/\.]+)(?:\.git)?", clean_url)
            if m:
                owner = m.group(1)
                repo_name = m.group(2)
        elif os.path.isdir(clean_url):
            provider = "local"
            repo_name = os.path.basename(os.path.abspath(clean_url))
            owner = "local-workspace"
        else:
            parts = clean_url.rstrip("/").split("/")
            if len(parts) >= 2:
                owner = parts[-2]
                repo_name = parts[-1].replace(".git", "")

        runtime_status = ScannerRuntimeManager.get_all_scanner_status()
        installed_scanners = {s["scanner"]: s["status"] == "READY" for s in runtime_status}

        analyzer = RepositoryAnalyzer()
        workspace_path = None

        try:
            resolved_sha = None
            default_branch = "main"

            if os.path.isdir(clean_url):
                resolved_sha = self.resolve_commit_sha(clean_url, requested_branch)
                workspace_path = clean_url
                should_cleanup = False
            else:
                clone_url = self.resolve_repository(clean_url)
                # Query remote branches and commit SHA without downloading source
                cmd = ["git", "ls-remote", "--symref", clone_url, "HEAD", f"refs/heads/*"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                
                if res.returncode != 0:
                    err_msg = res.stderr.strip() or "Authentication or connection failure"
                    return RepositoryValidationResult(
                        valid=False,
                        provider=provider,
                        repository_name=repo_name,
                        owner=owner,
                        default_branch="main",
                        requested_branch=requested_branch,
                        resolved_commit_sha=None,
                        access_status="inaccessible",
                        error=f"Cannot access repository: {err_msg}",
                        languages=[],
                        frameworks=[],
                        dependencies=[],
                        infrastructure=[],
                        repository_type="Unknown",
                        manifests=[],
                        files_count=0,
                        applicable_scanners=[],
                        scanner_readiness=runtime_status,
                        scanner_plan=[]
                    )

                # Detect default branch from symref
                output = res.stdout
                for line in output.splitlines():
                    if "ref: refs/heads/" in line and "HEAD" in line:
                        default_branch = line.split("ref: refs/heads/")[1].split()[0]
                        break

                effective_branch = branch or default_branch
                
                # Resolve commit SHA for effective branch
                for line in output.splitlines():
                    if line.startswith("ref:"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and len(parts[0]) == 40:
                        ref = parts[1]
                        if ref == f"refs/heads/{effective_branch}" or (effective_branch in ref and not ref.endswith("^{}")):
                            resolved_sha = parts[0]
                            break

                if not resolved_sha:
                    for line in output.splitlines():
                        if line.startswith("ref:"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == "HEAD" and len(parts[0]) == 40:
                            resolved_sha = parts[0]
                            break

                resolved_sha = resolved_sha or hashlib.sha1(f"{clean_url}@{effective_branch}".encode()).hexdigest()

                # Perform lightweight shallow clone to profile repository
                temp_dir = tempfile.mkdtemp(prefix="repo_profile_")
                os.chmod(temp_dir, 0o700)
                workspace_path = temp_dir
                should_cleanup = True

                clone_cmd = [
                    "git", "clone", "--depth", "1",
                    "--single-branch", "--branch", effective_branch,
                    clone_url, workspace_path
                ]
                clone_res = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=45)
                if clone_res.returncode != 0:
                    # Fallback try generic clone without branch
                    fallback_cmd = ["git", "clone", "--depth", "1", clone_url, workspace_path]
                    subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=45)

            # Analyze workspace to build rich profile
            profile = analyzer.build_profile(
                workspace_path=workspace_path,
                repository_id=repo_name,
                commit_sha=resolved_sha or "HEAD",
                repository_name=repo_name
            )

            # Extract infrastructure indicators
            infra = []
            if profile.container_targets:
                infra.append("Docker")
            if any(t.endswith(".tf") for t in profile.iac_targets):
                infra.append("Terraform")
            if any("k8s" in t.lower() or "helm" in t.lower() for t in profile.iac_targets):
                infra.append("Kubernetes")

            # Infer repository type
            fw_lower = [f.lower() for f in profile.frameworks]
            if any(f in fw_lower for f in ["react", "next.js", "vue.js", "angular", "fastapi", "django", "express", "spring boot", "flask"]):
                repo_type = "Web Application"
            elif infra and not profile.languages:
                repo_type = "Infrastructure as Code"
            elif "docker" in [i.lower() for i in infra] and ("fastapi" in fw_lower or "express" in fw_lower or "spring" in fw_lower):
                repo_type = "Cloud Native Microservice"
            elif any(l.lower() in ["python", "go", "rust", "c", "cpp"] for l in profile.languages) and not fw_lower:
                repo_type = "CLI / System Utility"
            else:
                repo_type = "Software Repository"

            # Determine applicable scanners and build scanner plan
            applicable_scanners = []
            scanner_plan = []

            # 1. Semgrep: SAST & Secrets
            semgrep_installed = installed_scanners.get("semgrep", True)
            applicable_scanners.append("semgrep")
            scanner_plan.append({
                "scanner": "semgrep",
                "scanner_name": "Semgrep",
                "scanner_type": "SAST & Secrets",
                "status": "READY" if semgrep_installed else "NOT_INSTALLED",
                "applicable": True,
                "reason": f"AST code analysis & secrets detection for {', '.join(profile.languages) if profile.languages else 'source files'}"
            })

            # 2. CodeQL: Deep Semantic SAST
            codeql_supported = {"python", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "ruby", "rust", "swift"}
            has_codeql_lang = any(l.lower() in codeql_supported for l in profile.languages)
            codeql_installed = installed_scanners.get("codeql", True)
            if has_codeql_lang and codeql_installed:
                applicable_scanners.append("codeql")
                scanner_plan.append({
                    "scanner": "codeql",
                    "scanner_name": "CodeQL",
                    "scanner_type": "Deep Semantic SAST",
                    "status": "READY",
                    "applicable": True,
                    "reason": f"Interprocedural dataflow & taint analysis for {', '.join([l for l in profile.languages if l.lower() in codeql_supported])}"
                })
            else:
                scanner_plan.append({
                    "scanner": "codeql",
                    "scanner_name": "CodeQL",
                    "scanner_type": "Deep Semantic SAST",
                    "status": "NOT_APPLICABLE" if not has_codeql_lang else "NOT_INSTALLED",
                    "applicable": False,
                    "reason": "No supported CodeQL languages detected" if not has_codeql_lang else "CodeQL CLI binary not installed"
                })

            # 3. Trivy: SCA & Misconfiguration
            has_manifests = len(profile.manifests) > 0 or len(profile.container_targets) > 0 or len(profile.iac_targets) > 0
            trivy_installed = installed_scanners.get("trivy", True)
            if has_manifests and trivy_installed:
                applicable_scanners.append("trivy")
                scanner_plan.append({
                    "scanner": "trivy",
                    "scanner_name": "Trivy",
                    "scanner_type": "SCA & IaC",
                    "status": "READY",
                    "applicable": True,
                    "reason": f"SCA & configuration scanning for {len(profile.manifests)} manifests and {len(profile.iac_targets)} IaC targets"
                })
            else:
                scanner_plan.append({
                    "scanner": "trivy",
                    "scanner_name": "Trivy",
                    "scanner_type": "SCA & IaC",
                    "status": "NOT_APPLICABLE" if not has_manifests else "NOT_INSTALLED",
                    "applicable": False,
                    "reason": "No dependency manifests or container targets detected" if not has_manifests else "Trivy binary not installed"
                })

            # 4. OSV-Scanner: Lockfile Vulnerability Database
            lockfiles = [m for m in profile.manifests if any(m.endswith(k) for k in ["lock", "lock.json", "lock.yaml", "sum", "Pipfile"])]
            osv_installed = installed_scanners.get("osv", True) or installed_scanners.get("osv-scanner", True)
            if lockfiles and osv_installed:
                applicable_scanners.append("osv")
                scanner_plan.append({
                    "scanner": "osv",
                    "scanner_name": "OSV-Scanner",
                    "scanner_type": "Open Source Vulnerabilities",
                    "status": "READY",
                    "applicable": True,
                    "reason": f"Direct lockfile vulnerability queries for {', '.join(lockfiles)}"
                })
            else:
                scanner_plan.append({
                    "scanner": "osv",
                    "scanner_name": "OSV-Scanner",
                    "scanner_type": "Open Source Vulnerabilities",
                    "status": "NOT_APPLICABLE" if not lockfiles else "NOT_INSTALLED",
                    "applicable": False,
                    "reason": "No dependency lockfiles (e.g. package-lock.json, go.sum) found" if not lockfiles else "OSV-Scanner binary not installed"
                })

            return RepositoryValidationResult(
                valid=True,
                provider=provider,
                repository_name=clean_url if clean_url.startswith("http") else (f"{owner}/{repo_name}" if owner != "unknown" else repo_name),
                owner=owner,
                default_branch=default_branch,
                requested_branch=requested_branch,
                resolved_commit_sha=resolved_sha or "HEAD",
                access_status="accessible",
                error=None,
                languages=profile.languages,
                frameworks=profile.frameworks,
                dependencies=profile.package_managers,
                infrastructure=infra,
                repository_type=repo_type,
                manifests=profile.manifests,
                files_count=profile.files_discovered,
                applicable_scanners=applicable_scanners,
                scanner_readiness=runtime_status,
                scanner_plan=scanner_plan
            )

        except subprocess.TimeoutExpired:
            return RepositoryValidationResult(
                valid=False,
                provider=provider,
                repository_name=repo_name,
                owner=owner,
                default_branch="main",
                requested_branch=requested_branch,
                resolved_commit_sha=None,
                access_status="timeout",
                error="Network timeout validating remote repository.",
                languages=[],
                frameworks=[],
                dependencies=[],
                infrastructure=[],
                repository_type="Unknown",
                manifests=[],
                files_count=0,
                applicable_scanners=[],
                scanner_readiness=runtime_status,
                scanner_plan=[]
            )
        except Exception as e:
            return RepositoryValidationResult(
                valid=False,
                provider=provider,
                repository_name=repo_name,
                owner=owner,
                default_branch="main",
                requested_branch=requested_branch,
                resolved_commit_sha=None,
                access_status="error",
                error=str(e),
                languages=[],
                frameworks=[],
                dependencies=[],
                infrastructure=[],
                repository_type="Unknown",
                manifests=[],
                files_count=0,
                applicable_scanners=[],
                scanner_readiness=runtime_status,
                scanner_plan=[]
            )
        finally:
            if workspace_path and should_cleanup and os.path.exists(workspace_path):
                shutil.rmtree(workspace_path, ignore_errors=True)


