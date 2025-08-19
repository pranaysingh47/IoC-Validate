#!/usr/bin/env python3
"""
IoC Validation Configuration Utility
Creates and manages configuration files for the IoC validation script.
"""

import os
import sys

def create_config():
    """Create a config.env file from the template"""
    script_dir = os.path.dirname(__file__)
    template_path = os.path.join(script_dir, 'config.env.example')
    config_path = os.path.join(script_dir, 'config.env')
    
    if os.path.exists(config_path):
        print(f"Config file already exists at: {config_path}")
        response = input("Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("Configuration cancelled.")
            return
    
    if not os.path.exists(template_path):
        print(f"Template file not found: {template_path}")
        return
    
    # Copy template to config file
    with open(template_path, 'r') as template:
        with open(config_path, 'w') as config:
            config.write(template.read())
    
    print(f"Created configuration file: {config_path}")
    print("Please edit this file to set your API keys and preferences.")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'create':
        create_config()
    else:
        print("IoC Validation Configuration Utility")
        print("Usage: python configure.py create")
        print("This will create a config.env file for customizing settings.")

if __name__ == "__main__":
    main()