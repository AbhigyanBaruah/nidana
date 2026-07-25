import os
from nidana import stream_functions

def main():
    # Force absolute paths so Windows cmd.exe cannot get confused
    r2_path = os.path.abspath(r"test_bins\r2\radare2.exe")
    bin_path = os.path.abspath(r"test_bins\ping.exe")
    
    print(f"Targeting r2 at: {r2_path}")
    print(f"Targeting binary at: {bin_path}")
    
    if not os.path.exists(r2_path):
        print("ERROR: radare2.exe not found at the absolute path!")
        return
        
    try:
        items = list(stream_functions(bin_path, r2_path))
        print(f"\nSuccessfully extracted {len(items)} functions!")
        
        if items:
            f0 = items[0]
            print(f"First function: {f0.name} | Blocks: {len(f0.blocks)} | Incomplete: {f0.analysis_incomplete}")
    except Exception as e:
        print(f"\nExtraction failed: {e}")

if __name__ == "__main__":
    main()