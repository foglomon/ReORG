# ReORG

### Overview

This plan outlines a Python application that automates file organization in a given directory using a local LLM for intelligent categorization to ensure privacy. The app will:

- Accept a target directory as input.
- Recursively scan all files.
- Use a local LLM (e.g., via Hugging Face Transformers or llama.cpp) to suggest meaningful, nested folder structures based on file metadata (name, extension, and optionally a content snippet).
- Move files to their new locations, creating folders as needed.
- Maintain a mapping of old-to-new paths.
- Scan text-based files post-move to replace any references to old file paths with the updated ones.

The app assumes primarily text-based files (e.g., code, docs, Markdown) for path replacement, as binary files (e.g., images, executables) can't be easily modified for string replacements. It handles relative and absolute paths carefully to avoid breaking references. Error handling will be included for issues like permission denies or LLM inference failures. Since the LLM runs locally, all operations are offline, enhancing data privacy by avoiding external API calls.

### Requirements

- **Python Version**: 3.8+ for modern features like pathlib.
- **Libraries**:
  - `os` and `shutil`: For file traversal, moving, and directory creation.
  - `pathlib`: For path manipulation (relative/absolute handling).
  - `re`: For regex-based path replacement in file contents.
  - LLM Integration: Use `transformers` from Hugging Face for loading and inferring with local models, or `llama-cpp-python` for efficient quantized models. No API key required.
  - Optional: `tqdm` for progress bars during long operations; `torch` if using GPU-accelerated models.
- **External Dependencies**: A downloaded local LLM model (e.g., Llama 3 or Mistral from Hugging Face Model Hub). Requires sufficient hardware (CPU/GPU with at least 8GB RAM for small models; larger models may need more). No internet access needed during runtime.
- **Assumptions**:
  - Files are local and accessible.
  - LLM prompts will be designed to output folder paths in a consistent format (e.g., "category/subcategory").
  - Path references in files are string literals (e.g., in code or configs); complex cases like encoded paths are out of scope.
  - Backup original directory before running to prevent data loss.
  - Local LLM inference may be slower than API calls; optimize with quantization or smaller models.

### Architecture

The app will be structured as a command-line tool with modular components:

1. **Main Script** (`organize_files.py`): Handles CLI arguments, orchestration, and logging.
2. **File Scanner Module**: Collects file metadata.
3. **LLM Classifier Module**: Loads and queries the local LLM for folder suggestions.
4. **Mover Module**: Handles directory creation and file moves, tracks path mappings.
5. **Updater Module**: Scans and replaces paths in text files.
6. **Utils Module**: Helper functions for path normalization, regex patterns, and error logging.

Use a config file (e.g., JSON) for customizable settings like LLM model path, prompt templates, ignored file extensions, dry-run mode, and hardware acceleration (e.g., CUDA).

### Step-by-Step Process

1. **Input and Setup**:

   - Parse CLI arguments: `python organize_files.py --target /path/to/dir --model-path /path/to/local/model --dry-run` (dry-run simulates without actual moves).
   - Validate target directory exists and is accessible.
   - Create a backup copy of the directory (optional, toggled via flag).
   - Initialize an empty dictionary for old_path -> new_path mappings.
   - Load the local LLM once at startup (e.g., using `pipeline("text-generation", model=model_path)` from transformers, or via llama.cpp for faster inference).

2. **Scan Files**:

   - Use `pathlib.Path.rglob('*')` to recursively collect all files (exclude directories).
   - For each file, store metadata: absolute path, relative path (from target dir), name, extension.
   - Filter out ignored files (e.g., .git, temp files) via config.
   - If file count > threshold (e.g., 100), batch LLM inferences for efficiency to manage memory and time.

3. **Classify with LLM**:

   - For each file (or batch), prepare a prompt: "Based on the file name '{filename}', extension '{ext}', and content snippet '{snippet}' (first 200 chars if text file), suggest a nested folder path like 'category/subcategory' for organization. Output only the path."
   - Run local LLM inference (e.g., via `pipeline(prompt, max_new_tokens=50)` or llama.cpp equivalent).
   - Parse response to get suggested path (handle errors like invalid output by retrying with adjusted parameters or defaulting to 'uncategorized').
   - Compute new absolute path: target_dir / suggested_path / filename.
   - Resolve conflicts: If new path already exists, append a suffix (e.g., \_1) or prompt user.
   - Add to mappings: old_abs_path -> new_abs_path, and compute relative versions.

4. **Organize Files**:

   - Sort moves to handle nested dependencies (e.g., move deepest files first).
   - For each file:
     - Create parent directories if needed (`pathlib.Path.mkdir(parents=True)`).
     - Move file using `shutil.move(old_path, new_path)`.
   - Log all moves; rollback on failure.

5. **Update Path References**:

   - Re-scan all files in the reorganized directory (now including new locations).
   - For text files (check extensions like .py, .md, .txt, .html):
     - Read content.
     - Use regex to find potential path strings (e.g., r'[&#34;\']([^)["\']' for quoted paths).
     - For each match, check if it matches any old relative or absolute path in the mappings.
     - If yes, replace with the corresponding new path (preserve relativity: compute new relative path from the referencing file's location).
     - Write updated content back to the file.
   - Handle edge cases: Escaped paths, URLs (exclude http://), partial matches (use longest-prefix replacement).
   - Skip binary files or use a library like `chardet` to detect encoding.

6. **Post-Processing and Output**:

   - Verify no broken references (optional: re-scan for old paths).
   - Generate a report: Summary of moves, updates, and any issues (e.g., as JSON or console output).
   - Clean up: Remove empty original folders.
   - Unload the LLM model to free resources.

### Potential Challenges and Mitigations

- **LLM Performance/Memory**: Local inference can be slow on CPU; mitigate by using quantized models (e.g., GGUF format with llama.cpp), batching, or GPU acceleration if available.
- **Inaccurate Classifications**: Allow user overrides via interactive mode or refine prompts with examples. Test models for consistency.
- **Path Relativity**: Always normalize paths (use `pathlib` for os-agnostic handling) and compute relatives dynamically during replacement.
- **Large Directories**: Add progress bars and chunk processing to avoid memory issues; limit batch sizes based on hardware.
- **Security**: Sanitize LLM outputs to prevent malicious paths (e.g., validate no ../). Don't execute code from files. Local execution ensures no data leaves the machine.
- **File Types**: Limit updates to UTF-8 text; log warnings for binaries.
- **Idempotency**: Ensure the app can be re-run without duplicating folders.
- **Model Setup**: Initial download of models requires internet, but runtime is offline; document setup steps in README.

### Implementation Tips

- Start with a prototype for a small directory, using a lightweight model like Phi-2 or TinyLlama for testing.
- Test with sample data: Create a test dir with nested files referencing each other.
- Extendability: Add flags for custom prompts, model selection, or inference parameters (e.g., temperature).
- Error Handling: Use try-except blocks extensively, with user-friendly messages for LLM loading failures or out-of-memory errors.
