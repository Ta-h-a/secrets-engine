import { spawn } from 'child_process';

/**
 * Extracts all text from a PDF file using pdfplumber (Python).
 * Returns the full text with page markers inserted.
 */
export function extractPdfText(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // Inline Python script — avoids writing a temp file
    const script = [
      'import sys, pdfplumber',
      'pages = []',
      'with pdfplumber.open(sys.argv[1]) as pdf:',
      '    for i, page in enumerate(pdf.pages):',
      '        text = page.extract_text(x_tolerance=3, y_tolerance=3)',
      '        if text and text.strip():',
      '            # Normalise unicode dashes / smart quotes',
      '            text = text.replace("\\u2014", "--").replace("\\u2013", "-")',
      '            text = text.replace("\\u2018", "\\\'").replace("\\u2019", "\\\'")',
      '            text = text.replace("\\u201c", "\\"").replace("\\u201d", "\\")',
      '            pages.append(f"=== PAGE {i+1} ===\\n{text}")',
      'print("\\n\\n".join(pages))',
    ].join('\n');

    const proc = spawn('python3', ['-c', script, filePath]);
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString('utf8'); });
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString('utf8'); });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`PDF extraction failed (exit ${code}): ${stderr.trim()}`));
      } else if (!stdout.trim()) {
        reject(new Error('PDF appears to be empty or image-only — no text could be extracted'));
      } else {
        resolve(stdout.trim());
      }
    });

    proc.on('error', (err) => reject(new Error(`Failed to spawn python3: ${err.message}`)));
  });
}
