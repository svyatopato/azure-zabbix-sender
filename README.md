# Overview

This repository contains an Azure Function code which uses [zabbix-utils](https://github.com/zabbix/python-zabbix-utils)
and custom socket wrapper (for PSK auth, since the library itself does not support tls encryption) to send Azure Alert 
Events via **Action group** with _Azure Function_ type. It accepts [Common Alert Schema]() with some required custom 
properties: 
* host - host in Zabbix which has trapper item configured;
* key - trapper item key.

---

## Prerequisites

Before running the function locally, ensure you have the following installed:

- Linux distribution with OpenSSL installed (e.g. Ubuntu, or wsl with Linux distro installed on Windows machine and run
app from there)
- [Python 3.11](https://www.python.org/downloads/release/python-3119/)
- [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) (optional)
- Any editor with _Python_ support

### Notes
Probably can be run on Windows as well, but it failed to properly make use of _ECDHE-PSK-AES128-CBC-SHA256_ cypher, 
although I had OpenSSL installed on my Windows machine (sslpsk3 - python PSK lib relies on OpenSSL)

---

## Running Locally (Linux or wsl with Linux distro)

1. **Set required env vars in `local.settings.json` (copy from `local.settings.json.example`)**. 

    **Env vars:** 
    * _ZABBIX_SERVER_HOST_ - zabbix host (ip or dns name);
    
    **Secrets:**
    * _ZABBIX_PSK_IDENTITY_ - PSK identity (configured in Zabbix);  
    * _ZABBIX_PSK_SECRET_ - PSK key (not a file, since it's impossible to mount file secrets in Function Apps in Azure;
   configured in Zabbix);  


2. **Create a virtual environment and activate it**

   ```sh
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   venv\Scripts\activate     # On Windows
   ```

3. **Install dependencies**

   ```sh
   pip install -r requirements.txt
   ```

4. **Start the function locally**

   ```sh
   func start
   ```

---

## Deploying to Azure

### **Using GitHub Actions (OpenID Connect)**

You must have **user managed identity** which has 'Website Contributor' role in your **Function App** with **federated 
credentials** for GH Actions. You can [find more info here](https://github.com/Azure/functions-action?tab=readme-ov-file#use-oidc-recommended).

If function is _not public_ and connected via **Private Endpoints** to some **VNet** you need to have dedicated **VM with GH Runner** and 
connection to that same **VNet**.

1. Create environment (name take from Federated Credentials of Managed Identity that has Website Contributor role in 
Function App: e.g. test, prod and don't forget to edit this list in `deploy.yaml`);

2. Set variables (some can be global if Function Apps share same configuration):
Find these in dedicated Function App configurations:
   * `AZURE_FUNCTIONAPP_NAME` _\[required\] \[environment specific\]_ - function app name (is unique globally between 
   subscriptions and resource groups);
   * `AZURE_FUNCTIONAPP_PACKAGE_PATH` _\[optional\] \[default: '.'\]_ - path in the repo to the function;
   * `PYTHON_VERSION` _\[optional\] \[default: 3.11\]_ - python version in the Function App environment.

3. Set secrets (environment specific):
Find these in dedicated **Subscription** and **Managed identity** resources on Azure Portal or via Azure CLI:
   * `AZURE_CLIENT_ID` _\[required\]_ - find in **Managed identity** overview (can be copied from `JSON view`);
   * `AZURE_TENANT_ID` _\[required\]_ - find in **Managed identity** overview (can be copied from `JSON view`);
   * `AZURE_SUBSCRIPTION_ID` _\[required\]_ - find in **Subscription** details.

#### Env vars and secrets
Set (if not already done) required env vars settings in **App Settings** in _Environment variables tab_. Secrets can be referenced from key 
vault like `@Microsoft.KeyVault(SecretUri=https://<KEYVAULT_NAME>.vault.azure.net/secrets/<SECRET_NAME>/)`.


#### ! Note
After merge/push to `main` or `master` it'll deploy to default environment configured in `deploy.yaml`, edit this if you want 
other specific environment to be deployed to, or run `Deploy Azure Function` action manually from **GH Actions** and 
choose the one you want.

---

## Monitoring and Logs

- View logs with Azure CLI:
  ```sh
  az functionapp log tail --name _func-name_ --resource-group _resource-group-name_
  ```
- Check logs in [Azure Portal](https://portal.azure.com/).

---

## Clean Up

Once done testing locally run to exit **venv**:

```sh
deactivate
```

## 📜 License
This project is licensed under the [MIT License](LICENSE).  
You are free to use, modify, and distribute it as per the terms of the license.
