#Entry point that coordinates the scan.


from src.intake import inspect_file


def main():
    print("================================")
    print("         SAFE-OPEN")
    print("   Static File Security Scanner")
    print("================================")

    file_path = input("Enter the path of the file to scan: ").strip()
    file_path = file_path.strip('"')

    try:
        result = inspect_file(file_path)

        print("\nFile accepted for analysis.")
        print(f"Name: {result['file_name']}")
        print(f"Size: {result['file_size']} bytes")
        print(f"Extension: {result['extension']}")
        print(f"SHA-256: {result['sha256']}")

        print("\nBasic intake checks passed.")
        print("This is NOT yet a malware verdict.")

    except (OSError, ValueError) as error:
        print(f"\nFile could not be accepted: {error}")


if __name__ == "__main__":
    main()
