# OIDC / Workload Identity Federation Setup

This pipeline uses OIDC (OpenID Connect) to authenticate to Azure without storing any credentials in GitHub. No PATs, no service account keys, no secrets rotation headaches.

---

## How It Works

1. GitHub Actions generates a short-lived OIDC token for each workflow run
2. Azure validates the token against a configured federated credential
3. The runner receives a temporary Azure access token scoped to what it needs
4. The token expires when the job ends

No credentials are stored anywhere. Nothing to rotate. Nothing to leak.

---

## Azure Setup

### 1. Create an App Registration

```bash
az ad app create --display-name "github-security-pipeline"
```

Note the `appId` — this is your `AZURE_CLIENT_ID`.

### 2. Create a Service Principal

```bash
az ad sp create --id <appId>
```

### 3. Add Federated Credentials

```bash
az ad app federated-credential create \
  --id <appId> \
  --parameters '{
    "name": "github-actions-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Add additional federated credentials for other branches or pull requests as needed:

```bash
# For pull requests
az ad app federated-credential create \
  --id <appId> \
  --parameters '{
    "name": "github-actions-pr",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:YOUR_ORG/YOUR_REPO:pull_request",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

### 4. Grant Storage Permissions

```bash
az role assignment create \
  --assignee <appId> \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RG/providers/Microsoft.Storage/storageAccounts/YOUR_STORAGE_ACCOUNT"
```

---

## GitHub Setup

Add the following as **repository variables** (not secrets — these are not sensitive):

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | App registration client ID |
| `AZURE_TENANT_ID` | Your Azure tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID |
| `STORAGE_ACCOUNT_NAME` | Azure Blob Storage account name |
| `STORAGE_CONTAINER_NAME` | Container name for scan results |

Go to: **Repository → Settings → Secrets and variables → Actions → Variables**

---

## Verifying It Works

After your first successful run, you should see:

1. The `OIDC login to Azure` step completing without credentials
2. A new blob appearing in your storage container at `{repo}/{run_id}/aggregated-results.json`
3. No Azure credentials anywhere in your workflow logs

---

## Troubleshooting

**`AADSTS70021: No matching federated identity record found`**
→ The subject claim in your federated credential doesn't match. Check that the branch name in the credential matches what you're pushing to.

**`AuthorizationPermissionMismatch`**
→ The app registration doesn't have Storage Blob Data Contributor on the correct scope. Check the role assignment.

**`id-token: write` permission missing**
→ Ensure `permissions: id-token: write` is set at the workflow or job level.
