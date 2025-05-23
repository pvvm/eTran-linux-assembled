import os
import shutil

def process_common_folders(dir_a, dir_b):
    if not os.path.isdir(dir_a) or not os.path.isdir(dir_b):
        print("TESTE")
        return

    for file in os.listdir(dir_a):
        path_a = os.path.join(dir_a, file)
        path_b = os.path.join(dir_b, file)

        if os.path.isfile(path_a) and file.endswith('.S'):
            if not os.path.exists(path_b):
                os.makedirs(dir_b, exist_ok=True)
                shutil.copy2(path_a, path_b)
                print(f"Copied: {path_a} -> {path_b}")
            else:
                print(f"Skipped (exists): {path_b}")

    for name in os.listdir(dir_a):
        sub_a = os.path.join(dir_a, name)
        sub_b = os.path.join(dir_b, name)

        if os.path.isdir(sub_a) and os.path.isdir(sub_b):
            process_common_folders(sub_a, sub_b)

if __name__ == "__main__":
    folder_A = "linux"
    folder_B = "eTran-linux-assembled"
    process_common_folders(folder_A, folder_B)
