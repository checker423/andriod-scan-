# DroidScan Pro

DroidScan Pro is a desktop application (with a Flask backend) that connects to Android devices via ADB to perform security scans, monitor device vitals (battery, storage, RAM), and manage background processes.

## Prerequisites

1.  **Python 3.8+** installed on your system.
2.  **ADB (Android Debug Bridge)** must be installed and added to your system's PATH.
3.  An Android device connected via USB with **USB Debugging enabled**.

## Installation & Setup

1.  **Clone or download the repository:**
    ```bash
    git clone <your-github-repo-url>
    cd DroidScanPro
    ```

2.  **Create a virtual environment (Recommended):**
    ```bash
    python -m venv .venv
    ```

3.  **Activate the virtual environment:**
    - On Windows:
      ```bash
      .venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      source .venv/bin/activate
      ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Running the Application

Start the Flask server by running:

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`. Open this URL in your web browser to access the DroidScan Pro dashboard.

## Important Notes

*   **ADB Authorization:** The first time you connect your device, you may need to accept an RSA key prompt on your Android device to allow USB debugging from your computer.
*   The `.gitignore` file is already set up to exclude unnecessary files like `__pycache__`, `.idea`, `.venv`, and database files from being uploaded to GitHub.
