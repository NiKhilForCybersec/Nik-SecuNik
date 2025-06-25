"""
Fix FastAPI parameter issues in all API files
"""
import os
import re
from fastapi import APIRouter, Query, Depends, HTTPException
from pathlib import Path as PathLib  # Use PathLib for file system paths

def fix_fastapi_params_in_file(file_path):
    """Fix FastAPI parameter issues in a single file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        return False
    
    original_content = content
    
    # Fix imports - ensure Path is imported if needed
    if 'from fastapi import' in content and '/{' in content:
        # Check if Path is imported
        fastapi_import_match = re.search(r'from fastapi import ([^\n]+)', content)
        if fastapi_import_match:
            imports = fastapi_import_match.group(1)
            if 'Path' not in imports and ('Query' in content and '/{' in content):
                # Add Path to imports
                new_imports = imports.rstrip() + ', Path'
                content = content.replace(
                    f'from fastapi import {imports}',
                    f'from fastapi import {new_imports}'
                )
    
    # Find all route definitions with path parameters
    route_pattern = r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
    
    for match in re.finditer(route_pattern, content):
        route_path = match.group(2)
        
        # Extract path parameters from the route
        path_params = re.findall(r'\{(\w+)\}', route_path)
        
        if path_params:
            # Find the function definition after this route
            func_start = match.end()
            func_match = re.search(r'async def (\w+)\s*\((.*?)\):', content[func_start:], re.DOTALL)
            
            if func_match:
                func_name = func_match.group(1)
                params_str = func_match.group(2)
                
                # Check each path parameter
                for param in path_params:
                    # Look for this parameter using Query incorrectly
                    query_pattern = rf'{param}\s*:\s*[^=]+\s*=\s*Query\s*\('
                    if re.search(query_pattern, params_str):
                        # Replace Query with Path for this parameter
                        params_str = re.sub(
                            rf'({param}\s*:\s*[^=]+\s*=\s*)Query\s*\(',
                            r'\1Path(',
                            params_str
                        )
                
                # Replace the function parameters in the content
                old_func = f'async def {func_name}({func_match.group(2)}):'
                new_func = f'async def {func_name}({params_str}):'
                content = content.replace(old_func, new_func)
    
    # Fix common patterns
    replacements = [
        # Fix regex to pattern in Query/Path
        (r'Query\((.*?)regex=', r'Query(\1pattern='),
        (r'Path\((.*?)regex=', r'Path(\1pattern='),
        
        # Fix ... to Ellipsis if needed
        (r'=\s*Query\(\.\.\.,', r'= Query(...,'),
        (r'=\s*Path\(\.\.\.,', r'= Path(...,'),
    ]
    
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)
    
    # Save if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed FastAPI params in: {file_path}")
        return True
    return False

def main():
    """Fix all API files in the backend"""
    backend_dir = Path(__file__).parent
    api_dir = backend_dir / "api"
    fixed_count = 0
    
    # Process all Python files in api directory
    if api_dir.exists():
        for py_file in api_dir.glob("*.py"):
            if py_file.name not in ["__init__.py", "__pycache__"]:
                if fix_fastapi_params_in_file(py_file):
                    fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")
    
    # Also check for specific issue in history.py
    history_file = api_dir / "history.py"
    if history_file.exists():
        print("\nChecking history.py specifically...")
        with open(history_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Look for the export_history function
        if 'export_history' in content and '/{format}' in content:
            print("Found export_history with path parameter")
            # Make sure it's using Path not Query
            if 'format: str = Query' in content:
                print("ERROR: format parameter is using Query instead of Path!")
                print("Please manually fix this in history.py")

if __name__ == "__main__":
    main()