<h1 align="center">WSS: WordPress Security Scanner</h1>

*Python* support:

- 3.13.1

*OS's* support:

- Ubuntu latest

--------------------------------------------------------------------------------------

<!--<h1 align="center">WSS:</b> In Development mode!!!</h1>-->

~WSS:In Development mode!!!~

<p align="center">
<img src="https://github.com/nu11secur1ty/WSS/blob/main/screen/logo.gif"/>
</p>

- - *Google Dorks* 

## WARNING! Every malicious action from your side will be your responsibility!

```
index of" inurl:wp-content/                      7,370,000 results 
inurl:"/wp-content/plugins/wp-shopping-cart/"    281,000 results
inurl:wp-content/plugins/wp-dbmanager/"          11,000 results
```

WSS is a black box WordPress vulnerability scanner that can scan remote WordPress installations to find security issues.

![python](https://img.shields.io/badge/python-3.x-green.svg) ![license](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)

![screen_1](https://raw.githubusercontent.com/nu11secur1ty/WSS/master/screen/main.png)

## Installation
```
$ git clone https://github.com/nu11secur1ty/WSS.git wss
$ cd wss
$ pip3 install -r requirements.txt
$ python wss.py
```
## Usage
### Generic Scan

`python3 wss.py --url https://www.xxxxxxx.com --verbose`

* __Output__

```
[ + ] Target: http://localhost/wordpress/
[ + ] Starting: 07:23:02

[ + ] Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
[ i ] Checking Full Path Disclosure...
[ i ] Checking wp-config backup file...
[ + ] wp-config.php available at: http://localhost/wordpress/wp-config.php
[ i ] Checking common files...
[ + ] LICENSE.txt file was found at: http://localhost/wordpress/LICENSE.txt
[ + ] readme.html file was found at: http://localhost/wordpress/readme.html
[ i ] Checking directory listing...
[ + ] Dir "/wp-admin/css" listing enable at: http://localhost/wordpress/wp-admin/css/
[ + ] Dir "/wp-admin/images" listing enable at: http://localhost/wordpress/wp-admin/images/
[ + ] Dir "/wp-admin/includes" listing enable at: http://localhost/wordpress/wp-admin/includes/
[ + ] Dir "/wp-admin/js" listing enable at: http://localhost/wordpress/wp-admin/js/
[ + ] Dir "/wp-content/uploads" listing enable at: http://localhost/wordpress/wp-content/uploads/
[ + ] Dir "/wp-includes/" listing enable at: http://localhost/wordpress/wp-includes/
[ + ] Dir "/wp-includes/js" listing enable at: http://localhost/wordpress/wp-includes/js/
[ + ] Dir "/wp-includes/Text" listing enable at: http://localhost/wordpress/wp-includes/Text/
[ + ] Dir "/wp-includes/css" listing enable at: http://localhost/wordpress/wp-includes/css/
[ + ] Dir "/wp-includes/images" listing enable at: http://localhost/wordpress/wp-includes/images/
[ + ] Dir "/wp-includes/pomo" listing enable at: http://localhost/wordpress/wp-includes/pomo/
[ + ] Dir "/wp-includes/theme-compat" listing enable at: http://localhost/wordpress/wp-includes/theme-compat/
[ i ] Checking wp-loging protection...
[ i ] Checking robots paths...
[ i ] Checking WordPress version...
[ + ] Running WordPress version: 6.7.1

[ i ] Passive enumeration themes...
[ + ] Name: twentytwentyfour
[ i ] Checking themes changelog...
[ i ] Checking themes full path disclosure...
[ i ] Checking themes license...
[ i ] Checking themes readme...
[ i ] Checking themes directory listing...
[ i ] Checking theme vulnerabilities...
  |   Not found vulnerabilities

[ i ] Passive enumeration plugins...
[ + ] Not found plugins with passive enumeration
[ i ] Enumerating users...
-------------------------
| ID | Username | Login |
-------------------------
|  0 | admin    | admin |
|  1 |          | admin |
-------------------------
```
### Bruteforce Login

`python3 wss.py --url https://www.xxxxxxx.com --brute --user test --wordlist wordlist.txt --verbose`

* __Output__

```
$$       $$   $$$$$$    $$$$$$
$$   $   $$  $$    $$  $$    $$
$$  $$$  $$  $$        $$
$$ $$ $$ $$   $$$$$$    $$$$$$
$$$$   $$$$        $$        $$
$$$     $$$  $$    $$  $$    $$
$$       $$   $$$$$$    $$$$$$
v4.0

WSS - Wordpress Security Scanner
by nu11secur1ty


[ + ] Target: http://localhost/wordpress/
[ + ] Starting: 07:25:58

[ + ] Brute Forcing Login via XMLRPC...When you see any valid credentials press Ctrl + C to exit.
[ i ] Setting user: admin
[ + ] Valid Credentials:

-----------------------
| Username | Passowrd |
-----------------------
| admin    | password |
-----------------------
```

### Scan plugin,theme and wordpress code

`python3 wss.py --scan <dir/file> --verbose`

__Note__: Testing Akismet Directory Plugin https://plugins.svn.wordpress.org/akismet

* __Output__

```
----------------------------------------
$$       $$   $$$$$$    $$$$$$
$$   $   $$  $$    $$  $$    $$
$$  $$$  $$  $$        $$
$$ $$ $$ $$   $$$$$$    $$$$$$
$$$$   $$$$        $$        $$
$$$     $$$  $$    $$  $$    $$
$$       $$   $$$$$$    $$$$$$
v4.0

WSS - Wordpress Security Scanner
by nu11secur1ty
----------------------------------------

[ + ] Checking PHP code...
[ + ] Scanning directory...
[ i ] Scanning trunk/class.akismet.php file
----------------------------------------------------------------------------------------------------------
| Line | Possibile Vuln.      | String                                                                   |
----------------------------------------------------------------------------------------------------------
|  597 | Cross-Site Scripting | [b"$_GET['action']", b"$_GET['action']"]                                 |
|  601 | Cross-Site Scripting | [b"$_GET['for']", b"$_GET['for']"]                                       |
|  140 | Cross-Site Scripting | [b"$_POST['akismet_comment_nonce']", b"$_POST['akismet_comment_nonce']"] |
|  144 | Cross-Site Scripting | [b"$_POST['_ajax_nonce-replyto-comment']"]                               |
|  586 | Cross-Site Scripting | [b"$_POST['status']", b"$_POST['status']"]                               |
|  588 | Cross-Site Scripting | [b"$_POST['spam']", b"$_POST['spam']"]                                   |
|  590 | Cross-Site Scripting | [b"$_POST['unspam']", b"$_POST['unspam']"]                               |
|  592 | Cross-Site Scripting | [b"$_POST['comment_status']", b"$_POST['comment_status']"]               |
|  599 | Cross-Site Scripting | [b"$_POST['action']", b"$_POST['action']"]                               |
|  214 | Cross-Site Scripting | [b"$_SERVER['HTTP_REFERER']", b"$_SERVER['HTTP_REFERER']"]               |
|  403 | Cross-Site Scripting | [b"$_SERVER['REQUEST_TIME_FLOAT']", b"$_SERVER['REQUEST_TIME_FLOAT']"]   |
|  861 | Cross-Site Scripting | [b"$_SERVER['REMOTE_ADDR']", b"$_SERVER['REMOTE_ADDR']"]                 |
|  930 | Cross-Site Scripting | [b"$_SERVER['HTTP_USER_AGENT']", b"$_SERVER['HTTP_USER_AGENT']"]         |
|  934 | Cross-Site Scripting | [b"$_SERVER['HTTP_REFERER']", b"$_SERVER['HTTP_REFERER']"]               |
| 1349 | Cross-Site Scripting | [b"$_SERVER['REMOTE_ADDR']"]                                             |
----------------------------------------------------------------------------------------------------------
[ i ] Scanning trunk/wrapper.php file
[ + ] Not found vulnerabilities
[ i ] Scanning trunk/akismet.php file
-----------------------------------------------
| Line | Possibile Vuln.    | String          |
-----------------------------------------------
|   55 | Authorization Hole | [b'is_admin()'] |
-----------------------------------------------
[ i ] Scanning trunk/class.akismet-cli.php file
[ + ] Not found vulnerabilities
[ i ] Scanning trunk/class.akismet-widget.php file
[ + ] Not found vulnerabilities
[ i ] Scanning trunk/index.php file
[ + ] Not found vulnerabilities
[ i ] Scanning trunk/class.akismet-admin.php file
--------------------------------------------------------------------------------------------------------------------
| Line | Possibile Vuln.      | String                                                                             |
--------------------------------------------------------------------------------------------------------------------
|   39 | Cross-Site Scripting | [b"$_GET['page']", b"$_GET['page']"]                                               |
|  134 | Cross-Site Scripting | [b"$_GET['akismet_recheck']", b"$_GET['akismet_recheck']"]                         |
|  152 | Cross-Site Scripting | [b"$_GET['view']", b"$_GET['view']"]                                               |
|  190 | Cross-Site Scripting | [b"$_GET['view']", b"$_GET['view']"]                                               |
|  388 | Cross-Site Scripting | [b"$_GET['recheckqueue']"]                                                         |
|  841 | Cross-Site Scripting | [b"$_GET['view']", b"$_GET['view']"]                                               |
|  843 | Cross-Site Scripting | [b"$_GET['view']", b"$_GET['view']"]                                               |
|  850 | Cross-Site Scripting | [b"$_GET['action']"]                                                               |
|  851 | Cross-Site Scripting | [b"$_GET['action']"]                                                               |
|  852 | Cross-Site Scripting | [b"$_GET['_wpnonce']", b"$_GET['_wpnonce']"]                                       |
|  868 | Cross-Site Scripting | [b"$_GET['token']", b"$_GET['token']"]                                             |
|  869 | Cross-Site Scripting | [b"$_GET['token']"]                                                                |
|  873 | Cross-Site Scripting | [b"$_GET['action']"]                                                               |
|  874 | Cross-Site Scripting | [b"$_GET['action']"]                                                               |
| 1005 | Cross-Site Scripting | [b"$_GET['akismet_recheck_complete']"]                                             |
| 1006 | Cross-Site Scripting | [b"$_GET['recheck_count']"]                                                        |
| 1007 | Cross-Site Scripting | [b"$_GET['spam_count']"]                                                           |
|   31 | Cross-Site Scripting | [b"$_POST['action']", b"$_POST['action']"]                                         |
|  256 | Cross-Site Scripting | [b"$_POST['_wpnonce']"]                                                            |
|  260 | Cross-Site Scripting | [b'$_POST[$option]', b'$_POST[$option]']                                           |
|  267 | Cross-Site Scripting | [b"$_POST['key']"]                                                                 |
|  392 | Cross-Site Scripting | [b"$_POST['offset']", b"$_POST['offset']", b"$_POST['limit']", b"$_POST['limit']"] |
|  447 | Cross-Site Scripting | [b"$_POST['id']"]                                                                  |
|  448 | Cross-Site Scripting | [b"$_POST['id']"]                                                                  |
|  460 | Cross-Site Scripting | [b"$_POST['id']", b"$_POST['url']"]                                                |
|  461 | Cross-Site Scripting | [b"$_POST['id']"]                                                                  |
|  464 | Cross-Site Scripting | [b"$_POST['url']"]                                                                 |
|  388 | Cross-Site Scripting | [b"$_REQUEST['action']", b"$_REQUEST['action']"]                                   |
|  400 | Cross-Site Scripting | [b"$_SERVER['HTTP_REFERER']", b"$_SERVER['HTTP_REFERER']"]                         |
--------------------------------------------------------------------------------------------------------------------
[ i ] Scanning trunk/class.akismet-rest-api.php file
[ + ] Not found vulnerabilities

```
## Extensions:

[Extensions](https://github.com/nu11secur1ty/WSS/tree/main/extensions)

## Credits and Contributors
Original idea and script from WPScan Team (https://wpscan.org/)

## Useful links:
[URL-1](https://wpscan.com/)

[URL-2](https://wpscan.com/plugins/)

[URL-3](https://wpscan.com/themes/)

WPScan Vulnerability Database (https://wpvulndb.com/api)

## Demo when the target is protected:
[Patreon](https://www.patreon.com/posts/wss-blocking-get-120555453)
