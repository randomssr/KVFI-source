import os 
import subprocess
from pathlib import Path



# 遍历这个文件夹，找到里面的二进制文件
def is_binary_file(file_path):
    try:
        result =  subprocess.run(["file", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "ELF" in result.stdout and ("executable" in result.stdout or "shared object" in result.stdout):
            return True
        return False
    except Exception as e:
        print(f"Error using file command on {file_path}: {e}")
        return False
    
def find_binary_files(directory):
    binary_files = []
    p = Path(directory)
    for item in p.rglob('*'):
        # print(item)
        if not item.is_symlink() and item.is_file() and is_binary_file(item):
            print(item)
            binary_files.append(item)
    return binary_files




# if __name__ == "__main__":
#     print(find_binary_files(squash_root_path))