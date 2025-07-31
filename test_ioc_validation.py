import os
import pandas as pd
import subprocess

def test_script_runs_and_produces_output():
    # Prepare
    test_input = "example_input.txt"
    if not os.path.exists(test_input):
        with open(test_input, "w") as f:
            f.write("8.8.8.8\nmalicious[.]domain[.]com\nhxxps[:]//bad[.]site\n44d88612fea8a8f36de82e1278abb02f\n")
    # Run script
    subprocess.run(["python", "ioc_validation.py", test_input], check=True)
    # Find output file
    files = [f for f in os.listdir('.') if f.startswith("example_input_IoC_Validate") and f.endswith(".xlsx")]
    assert files, "No output Excel file found."
    # Check output contents
    df = pd.read_excel(files[0])
    assert "Original_IoC" in df.columns
    assert len(df) >= 4
    print("Test passed: Output file and contents are as expected.")

if __name__ == "__main__":
    test_script_runs_and_produces_output()