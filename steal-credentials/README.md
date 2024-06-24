# Steal Credentials VSCode Extension

The [VSCode API](https://code.visualstudio.com/api/references/vscode-api) provides extensions with functionality to store secrets via [SecretStorage.store(key, value)](https://code.visualstudio.com/api/references/vscode-api#SecretStorage).

It stores the secrets namespaced to the extension requesting the operation.

Still, nothing prevents an evil extension to use the underlying mechanisms to steal credentials for all extensions.

```mermaid
flowchart
	subgraph Code
	VSCODE["VSCode"]
	VSCODEAPI["VSCode API SecretStorage"]
	EXTENSION["VSCode Extension"]
	style EXTENSION fill:#337733,stroke:#333,stroke-width:4px
    ELECTRON["Electron safeStorage"]
    CHROMIUM["Chromium OSCrypt"]
    LIBSECRET["libsecret"]
    SQLITE["sqlite3"]
    DB["globalStorage/state.vscdb"]
	EVIL_EXTENSION["Evil Extension"]
	style EVIL_EXTENSION fill:#880000,stroke:#333,stroke-width:4px
    end

	KEYRING["keyring"]

	VSCODE --> EXTENSION
	EXTENSION --> |"store(key, value)"| VSCODEAPI

	VSCODEAPI --> |"encryptString(key, value)"| ELECTRON
	ELECTRON --> CHROMIUM
	CHROMIUM --> LIBSECRET
	LIBSECRET --> KEYRING

	VSCODEAPI --> |"store(extension, encryptedString)"| SQLITE
	SQLITE --> DB


	EVIL_EXTENSION --> LIBSECRET
	EVIL_EXTENSION --> SQLITE
```

## Threat Model

The overall attack flow is shown in the diagram below:

![malicious-vscode-extension-steal-credentials](./img/malicious-vscode-ext-steal-creds.png)

The raw file for the [attack flow builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/) is located alongside the diagram in the `img` directory.
