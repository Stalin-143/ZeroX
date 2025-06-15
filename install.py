import os
import sys
import shutil
import stat
import site
import venv

def install():
    try:
        # Detect if running in a virtual environment
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            site_packages = site.getsitepackages()[0]
            print(f"Detected virtual environment. Installing to {site_packages}")
        else:
            site_packages = site.getsitepackages()[0]
            print(f"Installing to system site-packages: {site_packages}")

        # Get the project directory
        project_dir = os.path.dirname(os.path.abspath(__file__))

        # Verify required directories and files
        required_items = ["main.py", "scanners", "utils"]
        for item in required_items:
            if not os.path.exists(os.path.join(project_dir, item)):
                raise FileNotFoundError(f"Required item not found: {item}")

        # Create temporary zerox module directory
        temp_zerox_dir = os.path.join(project_dir, "zerox_temp")
        os.makedirs(temp_zerox_dir, exist_ok=True)

        # Copy necessary files and directories
        for item in required_items:
            src = os.path.join(project_dir, item)
            dst = os.path.join(temp_zerox_dir, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
            print(f"Copied {item} to {dst}")

        # Create __init__.py
        with open(os.path.join(temp_zerox_dir, "__init__.py"), "w") as f:
            f.write("")
        print(f"Created __init__.py in {temp_zerox_dir}")

        # Copy to site-packages/zerox
        target_dir = os.path.join(site_packages, "zerox")
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(temp_zerox_dir, target_dir)
        print(f"Copied zerox module to {target_dir}")

        # Clean up temporary directory
        shutil.rmtree(temp_zerox_dir)
        print(f"Removed temporary directory {temp_zerox_dir}")

        # Create wrapper script
        python_executable = sys.executable
        wrapper_content = f"""#!/bin/bash
"{python_executable}" -c "from zerox.main import main; main()" "$@"
"""
        # Installation path for zerox command
        install_path = "/usr/local/bin/zerox" if os.name == 'posix' else os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Zerox", "zerox")

        # Write and install wrapper
        os.makedirs(os.path.dirname(install_path), exist_ok=True)
        with open(install_path, "w") as f:
            f.write(wrapper_content)
        if os.name == 'posix':
            os.chmod(install_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"Installed zerox command to {install_path}")

        print("Zerox installed successfully. Run 'zerox' from any terminal.")
    except Exception as e:
        print(f"Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install()