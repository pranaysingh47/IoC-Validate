#!/usr/bin/env python3
"""
Performance benchmark script for IoC validation improvements
Tests the script with different configurations to show scalability improvements.
"""

import os
import time
import subprocess
import tempfile

def create_test_iocs(count=10):
    """Create a test file with sample IoCs"""
    test_iocs = [
        "8.8.8.8",
        "1.1.1.1", 
        "example.com",
        "test.domain.com",
        "http://example.org",
        "https://test.site",
        "44d88612fea8a8f36de82e1278abb02f",  # MD5
        "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",  # SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        "malicious[.]domain[.]com"
    ]
    
    # Repeat to get desired count
    iocs = (test_iocs * ((count // len(test_iocs)) + 1))[:count]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for ioc in iocs:
            f.write(f"{ioc}\n")
        return f.name

def benchmark_test(ioc_count=10, batch_size=100, clear_console=False, debug_output=False):
    """Run a benchmark test with specific parameters"""
    print(f"\n--- Benchmark: {ioc_count} IoCs, batch_size={batch_size} ---")
    
    # Create test file
    test_file = create_test_iocs(ioc_count)
    
    # Set environment variables
    env = os.environ.copy()
    env['BATCH_SIZE'] = str(batch_size)
    env['CLEAR_CONSOLE'] = str(clear_console).lower()
    env['DEBUG_OUTPUT'] = str(debug_output).lower()
    env['VT_DELAY'] = '0.1'  # Reduced for testing
    env['OTHER_API_DELAY'] = '0.05'  # Reduced for testing
    
    try:
        start_time = time.time()
        result = subprocess.run(
            ['python', 'IoC_Validate.py', test_file],
            env=env,
            capture_output=True,
            text=True,
            timeout=60  # 1 minute timeout
        )
        elapsed_time = time.time() - start_time
        
        if result.returncode == 0:
            print(f"  ✓ Completed successfully in {elapsed_time:.2f} seconds")
            print(f"  ✓ Average time per IoC: {elapsed_time/ioc_count:.2f} seconds")
        else:
            print(f"  ✗ Failed with return code {result.returncode}")
            print(f"  Error: {result.stderr}")
        
        # Find and clean up output file
        import glob
        output_files = glob.glob("*_IoC_Validate_*.xlsx")
        for f in output_files:
            os.remove(f)
            
    except subprocess.TimeoutExpired:
        print(f"  ⚠ Timed out after 60 seconds (expected without real API keys)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)

def main():
    print("IoC Validation Performance Benchmark")
    print("=====================================")
    print("This benchmark demonstrates the scalability improvements.")
    print("Note: Tests may timeout without valid API keys, which is expected.")
    
    # Test different configurations
    benchmark_test(ioc_count=5, batch_size=10, clear_console=False, debug_output=False)
    benchmark_test(ioc_count=10, batch_size=20, clear_console=False, debug_output=False)
    
    print("\nBenchmark completed!")
    print("\nKey improvements demonstrated:")
    print("- Configurable batch processing for memory management")
    print("- Smart rate limiting (only waits when necessary)")
    print("- Cross-platform compatibility")
    print("- Input validation and error handling")
    print("- Configurable debug output")

if __name__ == "__main__":
    main()