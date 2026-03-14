import {
  SecretIngestRequest,
  SecretIngestResponse,
} from '../../shared/types';

const API_BASE = 'https://secretlens.onrender.com/api/v1';

export class SecretIngestionService {
  /**
   * Ingest a detected secret into SecretLens and get back a save script.
   *
   * @param secretType   - The type/category of the secret (e.g. "openai", "aws", "stripe")
   * @param secretValue  - The raw secret value found in source
   * @param language     - The language of the file the secret was found in
   * @param repoName     - The name of the git repository
   * @param environment  - The environment (e.g. "development", "production")
   */
  static async ingestSecret(
    secretType: string,
    secretValue: string,
    language: string,
    repoName: string = 'unknown',
    environment: string = 'development',
  ): Promise<SecretIngestResponse> {
    const requestBody: SecretIngestRequest = {
      secrets: [
        {
          type: secretType,
          language,
          secret_value: secretValue,
        },
      ],
      // Always request Python save scripts — boto3 is reliably available and
      // handles AWS credentials from env vars without extra dependencies.
      retrieval_language: 'python',
    };

    const url = new URL(`${API_BASE}/detected-secrets/ingest`);
    url.searchParams.set('repo_name', repoName);
    url.searchParams.set('environment', environment);

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      throw new Error(
        `SecretLens API error ${response.status}: ${errorText}`,
      );
    }

    const data = await response.json();
    return data as SecretIngestResponse;
  }
}
