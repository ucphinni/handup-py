import asyncio
import base64
import json
import socket
import sqlite3
import ssl
import sys

from aiohttp import web
from aiohttp_security import check_permission, \
    is_anonymous, remember, forget, \
    setup as setup_security, SessionIdentityPolicy
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aiohttp_session import get_session
from aiohttp_session import session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_sse import sse_response
from cryptography import fernet
from sqlalchemy import Column, Integer, Text, String, Boolean, DateTime, ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import aiohttp
import aiosqlite
import upnpy


# from string import letters
dbname = 'cf9.sqlite'
engine = create_engine('sqlite:///' + dbname, echo=True)
Base = declarative_base(bind=engine)


class ServerSSL(Base):
    __tablename__ = 'serverssl'
    id = Column(Integer, primary_key=True)
    fname_in_str = Column(Boolean, default=True)
    snl_hostname = Column(String(40), nullable=True)
    certif_str = Column(Text)
    key_str = Column(Text)


class SSHConnection(Base):
    __tablename__ = 'sshconnection'
    id = Column(Integer, primary_key=True)
    hostname = Column(Text)
    public_key = Column(Text)
    private_key = Column(Text)
    host_fingerprint = Column(Text, nullable=True)
    username = Column(Text)


class Profile(Base):
    __tablename__ = 'profile'
    id = Column(Integer, primary_key=True)
    name = Column(String(8), default='default', unique=True)

    use_upnp = Column(Boolean, default=True)

    public_listen_ip = Column(String(15), default='127.0.0.1')
    public_interface_ip = Column(String(15), default='127.0.0.1')
    public_port = Column(Integer, default=8080)
    public_ssl_id = Column(Integer, ForeignKey('serverssl.id'), nullable=True)
    public_ssl = relationship('ServerSSL', foreign_keys=[public_ssl_id])

    private_listen_ip = Column(String(15), default='127.0.0.1')
    private_port = Column(Integer, default=8081)
    private_ssl_id = Column(Integer, ForeignKey('serverssl.id'), nullable=True)
    private_ssl = relationship('ServerSSL', foreign_keys=[private_ssl_id])

#    reachmessh_id =         Column(Integer,ForeignKey('sshconnection.id'),       nullable = True)
#    reachmessh =            relationship('SSHConnection',foreign_keys=[reachmessh_id])

    hand_raise_service = Column(Boolean, default=True)
    tinycc_api_str = Column(
        Text, default='2ad7d98c-d247-4935-a90c-f1aa18f279ce')
    tinycc_custom_name = Column(String(15), default='jwkhtest')


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(20), unique=True, nullable=True)
    firstname = Column(String(20))
    lastname = Column(String(20))
    display_name = Column(String(20), unique=True, nullable=True)

    email = Column(String(45), unique=True)
    passwordhash = Column(String(64))
    passwordsalt = Column(String(10))
    sex = Column(String(1), default=True)
    is_baptized = Column(Boolean, default=True)
    roles = Column(String)
    active = Column(Boolean, default=False)

    cong_id = Column(Integer, ForeignKey('cong.id'), nullable=True)
    cong = relationship('Cong', foreign_keys=[cong_id])

    created_ip = Column(String(15))
    created_at = Column(DateTime)


class Cong(Base):
    __tablename__ = 'cong'
    id = Column(Integer, primary_key=True)
    name = Column(String(20))


Base.metadata.create_all()

Session = sessionmaker(bind=engine)
s = Session()
cfg = None
profile_name = 'default'


async def get_redirected_url(URL):
    async with aiohttp.ClientSession() as session:
        async with session.get(URL, allow_redirects=False) as response:
            Location = str(response).split("Location': \'")[1].split("\'")[0]
            return Location


def get_default_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


class Cfg:
    def __init__(self):
        pass

    def get_external_ip(self):
        ret = None

        try:
            import urllib.request
            ret = urllib.request.urlopen(
                'https://ident.me').read().decode('utf8')
            self.extern_ip_from = 'EXTERN_IP_WEBSITE'
        except Exception:
            self.extern_ip_from = None

        return ret


class UPnP2(upnpy.UPnP):
    def discover(self, delay=2, **headers):
        """
            Fix a bug in the this method where a pnp client can send bad data to this client
            and crash the program.  The fix is to ignore misbehaving clients.
        """

        discovered_devices = []
        for device in self.ssdp.m_search(
                discover_delay=delay, st='urn:schemas-upnp-org:device:InternetGatewayDevice:1', **headers):
            discovered_devices.append(device)

        self.discovered_devices = discovered_devices
        return self.discovered_devices


def upd_dict(arg, cmp_key, key, value):
    if cmp_key == key:
        arg[key] = value


def add_populate(action, ext_port=8081, protcol='TCP',
                 int_port=8081, int_client=get_default_ip()):
    arg = {}
    for field in action.get_input_arguments():
        a, f = arg, field['name']
        a[f] = ''
        upd_dict(a, f, 'NewRemoteHost', '')
        upd_dict(a, f, 'NewExternalPort', ext_port)
        upd_dict(a, f, 'NewProtocol', protcol)
        upd_dict(a, f, 'NewInternalPort', int_port)
        upd_dict(a, f, 'NewInternalClient', int_client)
        upd_dict(a, f, 'NewEnabled', 1)
        upd_dict(a, f, 'NewPortMappingDescription', 'Test Port')
        upd_dict(a, f, 'NewLeaseDuration', 0)
    return arg


def del_populate(action, ext_port=8081, protcol='TCP'):
    arg = {}
    for field in action.get_input_arguments():
        a, f = arg, field['name']
        a[f] = ''
        upd_dict(a, f, 'NewRemoteHost', '')
        upd_dict(a, f, 'NewExternalPort', ext_port)
        upd_dict(a, f, 'NewProtocol', protcol)
    return arg


class IGdMgr:
    def __init__(self, local_ip, local_port,
                 local_bind_ip, ext_port, protocol):
        self.local_ip, self.local_port = local_ip, local_port
        self.ext_port, self.protocol = ext_port, protocol
        self.service = self.ext_ip = None
        self.local_bind_ip = local_bind_ip
        self.cond = asyncio.Condition()
        self.upnp = UPnP2()
        self.device = None

    def igd_getadddelportacts(self):
        try:
            self.devices = self.upnp.discover()
            print(self.devices)
            self.device = self.upnp.get_igd()
            if self.device is None:
                raise TypeError()
        except Exception:
            raise
        self.addaction, delaction, exiaction, exisrvact, addsrvact, delsrvact \
            = None, None, None, None, None, None
        # self.ext_ip = await service.get_external_ip_address()
        self.local_ip = self.get_lan_ip(self.local_bind_ip)
        self.running = True
        done = False
        for service in self.device.get_services():
            addsrvact, delsrvact, exisrvact = None, None, None

            for action in service.get_actions():
                if action.name == 'AddPortMapping':
                    addaction = action
                    addsrvact = service
                elif action.name == 'DeletePortMapping':
                    delaction = action
                    delsrvact = service
                elif action.name == 'GetExternalIPAddress':
                    exiaction = action
                    exisrvact = service
                if addsrvact == delsrvact and addsrvact is not None \
                        and addsrvact == exisrvact:
                    done = True
                    break
            if done:
                break
        return (addsrvact,
                addaction,
                delaction if addsrvact == delsrvact else None,
                exiaction if addsrvact == exisrvact else None,
                )

    def setup(self):
        pass

    def get_lan_ip(self, bind_address='127.0.0.1'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(bind_address)
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = 'not-set'
        finally:
            s.close()
        return IP

    async def aiosleep(self, secs):
        await asyncio.sleep(secs)

    async def run(self):
        self.setup()
        self.running = True
        try:
            _, add_act, del_act, exi_act = self.igd_getadddelportacts()
            add_args = add_populate(add_act)
            add_act(**add_args)
            exi_ip = exi_act()
        except Exception:
            return
        while self.running:
            await self.aiosleep(60)
        del_args = del_populate(del_act)
        del_act(**del_args)

    def stop(self):
        self.running = False


FRIEND_HANDUP_HTML = """

<button class="ui-btn ui-corner-all" id="item">Press to Raise Hand</button><div id="container">
<script>

    var ip = location.host;

    $( "#item" ).bind("vmouseup",function(e) {
        $.ajax({
            type: 'POST',
            url: HandsUp.Settings.handUpUrl,
            data: "-",
            dataType: "json",
            success: function (resp) {
              $("#item").css("background-color","#000").css("color","#FFF")
            },
            error:function (resp) {
              $("#item").css("background-color","#F00").css("color","#0F0")

            }
            })
        }).bind("vmousedown", function(e) {
        $.ajax({
            type: 'POST',
            url: HandsUp.Settings.handUpUrl,
            data: "+",
            dataType: "json",
            success: function (resp) {
              $("#item").css("background-color","#00F").css("color","#FF0")

            },
            error:function (resp) {
              $("#item").css("background-color","#F00").css("color","#0F0")

            }
            })
        });

    </script>
"""

DISPLAY_HANDS_UP_HTML = """
<!DOCTYPE html>
<html>
<body>
<script>
var eventSource = new EventSource("/sse_handsup");
var names = []

eventSource.onmessage = function (event) {
    var mode = event.data.charAt(0)
    var name = event.data.substr(1)
    if (mode=='+')
        addBtn(name)
    else if (mode =='-') {
        delBtn(name);
    }
};

eventSource.onerror = function (event) {
    clearBtns()
}

function addBtn(name) {
    var btn = document.createElement("BUTTON");
    btn.innerHTML = name;
    btn.style = "font-size : {{FONT_SIZE}}px;"
    document.body.appendChild(btn);
    names.push(btn)
}
function delBtn(name) {

    var list = document.getElementsByTagName('button');

    for(i=list.length; i>0; i--){
        while (list.length >= i && list[i-1].innerHTML==name) {
            list[i-1].parentNode.removeChild(list[i-1])
        }
    }
}
function clearBtns() {
    var list = document.getElementsByTagName('button');

    for(i=list.length; i>0; i--){
        list[i-1].parentNode.removeChild(list[i-1])
    }
}

clearBtns()

</script>

</body>
</html>
"""


class Handler(AbstractAuthorizationPolicy):
    app_css = """
* Change html headers color */
h1,h2,h3,h4,h5 {
    color:#0071bc;
}
h2.mc-text-danger,
h3.mc-text-danger  {
    color:red;
}

/* Change border radius of icon buttons */
.ui-btn-icon-notext.ui-corner-all {
    -webkit-border-radius: .3125em;
    border-radius: .3125em;
}
/* Change color of jQuery Mobile page headers */
.ui-title {
    color:#fff;
}
/* Center-aligned text */
.mc-text-center {
    text-align:center;
}
/* Top margin for some elements */
.mc-top-margin-1-5 {
    margin-top:1.5em;
}
.bi-invalid-input {
    background-color:#fffacd!important;
}

.bi-invisible {
    display:none;
}

.bi-ctn-err {
    background-color:#ffe1cd;
    padding:0 .5em;
    margin-bottom:.5em;
    border: 1px solid #e9cfbd;
    border-radius:3px 3px;
}
"""
    std_header_html = """
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="css/themes/1/khapp.min.css" rel="stylesheet" />
<link href="https://cdnjs.cloudflare.com/ajax/libs/jquery-mobile/1.4.5/jquery.mobile.icons.min.css" rel="stylesheet" />
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.min.css" />
<link href="css/app.css" rel="stylesheet" />
<script src="http://code.jquery.com/jquery-2.1.1.min.js"></script>
<script src="http://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.min.js"></script>
<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha512.js"></script>
"""
    signup_succeeded_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Kingdom Hall Server</title>
""" + std_header_html + """
</head>
<body>
    <div data-role="page" data-bookit-page="index">
        <div data-role="header" data-theme="c">
            <h1>Book It</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h2 class="mc-text-center">Registration Succeeded</h2>
            <p class="mc-top-margin-1-5">Congratulations!  You are now registered with HandsUp.</p>
            <a href="sign-in.html" class="ui-btn ui-btn-b ui-corner-all">Sign In</a>
            <p></p>
        </div><!-- /content -->
    </div><!-- /page -->
</body>
</html>
"""

    begin_password_reset_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Kingdom Hall Server</title>
""" + std_header_html + """
</head>

<body>
    <div data-role="page">
        <div data-role="header" data-theme="c">
            <h1>Book It</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h3>Password Reset</h3>
            <label for="txt-email">Enter your email address</label>
            <input type="text" name="txt-email" id="txt-email" value="">
            <a href="#dlg-pwd-reset-sent" data-rel="popup" data-transition="pop" data-position-to="window" id="btn-submit" class="ui-btn ui-btn-b ui-corner-all mc-top-margin-1-5">Submit</a>
            <div data-role="popup" id="dlg-pwd-reset-sent" data-dismissible="false" style="max-width:400px;">
                <div data-role="header">
                    <h1>Password Reset</h1>
                </div>
                <div role="main" class="ui-content">
                    <h3>Check Your Inbox</h3>
                    <p>We sent you an email with instructions on how to reset your password. Please check your inbox and follow the instructions in the email.</p>
                    <div class="mc-text-center"><a href="end-password-reset.html" class="ui-btn ui-corner-all ui-shadow ui-btn-b mc-top-margin-1-5">OK</a></div>
                </div>
            </div>
        </div><!-- /content -->
    </div><!-- /page -->
</body>
</html>
"""
    end_password_reset_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Kingdom Hall Server</title>
""" + std_header_html + """
</head>
<body>
    <div data-role="page">
        <div data-role="header" data-theme="c">
            <h1>Kingdom Hall Login</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h3>Reset Password</h3>
            <label for="txt-tmp-password">Provisional Password</label>
            <input type="password" name="txt-tmp-password" id="txt-tmp-password" value="">
            <label for="txt-new-password">New Password</label>
            <input type="password" name="txt-new-password" id="txt-new-password" value="">
            <label for="txt-new-password-confirm">Confirm New Password</label>
            <input type="password" name="txt-new-password-confirm" id="txt-new-password-confirm" value="">
            <a href="#dlg-pwd-changed" data-rel="popup" data-transition="pop" data-position-to="window" id="btn-submit" class="ui-btn ui-btn-b ui-corner-all mc-top-margin-1-5">Submit</a>
            <div data-role="popup" id="dlg-pwd-changed" data-dismissible="false" style="max-width:400px;">
                <div data-role="header">
                    <h1>Done</h1>
                </div>
                <div role="main" class="ui-content">
                    <p>Your password was changed.</p>
                    <div class="mc-text-center"><a href="sign-in.html" class="ui-btn ui-corner-all ui-shadow ui-btn-b mc-top-margin-1-5">OK</a></div>

                </div>
            </div>
        </div><!-- /content -->
    </div><!-- /page -->

</body>
</html>
"""
    schema_sql = """
    INSERT INTO CONG (name) VALUES ('East WBoro');
    INSERT INTO CONG (name) VALUES ('West WBoro');
    INSERT INTO CONG (name) VALUES ('North WBoro');
    INSERT INTO CONG (name) VALUES ('Lumberton');
    INSERT INTO User (active,email,sex,is_baptized,firstname,lastname,name,passwordhash,roles,cong_id)
    VALUES(1,'ucphinni@gmail.com','M',1,'Cote','Phinnizee','C Phinnizee',
    'dcf4e7a137aa867d35c63d2bfc5e0417305ec15e0551e0c8db3a2f1ac01a4ddda393caa7d504b8b008865beae27e7e4fb53c121b95cf774d77a819e201732539',
    'admin',1);
"""
    EMAIL_NOT_FOUND = 0
    INVALID_PWD = 1
    DB_ERROR = 2
    EMAIL_ALREADY_EXISTS = 4
    COULD_NOT_CREATE_USER = 5
    PASSWORD_RESET_EXPIRED = 6
    PASSWORD_RESET_HASH_MISMATCH = 7
    PASSWORD_RESET_EMAIL_MISMATCH = 8
    COULD_NOT_RESET_PASSWORD = 9
    NOT_FOUND = 10
    PASSWORD_CONFIRM_MISMATCH = 11
    SESSION_NOT_FOUND = 12

    def __init__(self, cfg):
        global dbname
        self.cfg = cfg
        self.cond = asyncio.Condition()
        self.names = []
        self.dbname = dbname
        self.serversalt = None
        self.cong_html = None
        self.index_html = None
        self.cong_id = None

    async def do_resetpassword(self):
        pass

    async def async_create_schema(self):
        async with aiosqlite.connect(self.dbname) as conn:
            await conn.executescript(self.schema_sql)

    def create_schema(self):
        with sqlite3.connect(self.dbname) as conn:
            conn.executescript(self.schema_sql)

    async def handler_root(self, request):
        if self.index_html is None:
            await self.load_cong_html()
            self.index_html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta name="format-detection" content="telephone=no" />
    <meta name="msapplication-tap-highlight" content="no" />
    <!-- WARNING: for iOS 7, remove the width=device-width and height=device-height attributes. See https://issues.apache.org/jira/browse/CB-4323 -->
    <meta name="viewport" content="width=device-width, height=device-height, user-scalable=no, initial-scale=1, maximum-scale=1, minimum-scale=1, target-densitydpi=device-dpi" />
<script>
function includeHTML() {
  var z, i, elmnt, file, xhttp;
  /* Loop through a collection of all HTML elements: */
  z = document.getElementsByTagName("*");
  for (i = 0; i < z.length; i++) {
    elmnt = z[i];
    /*search for elements with a certain atrribute:*/
    file = elmnt.getAttribute("w3-include-html");
    if (file) {
      /* Make an HTTP request using the attribute value as the file name: */
      xhttp = new XMLHttpRequest();
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4) {
          if (this.status == 200) {elmnt.innerHTML = this.responseText;}
          if (this.status == 404) {elmnt.innerHTML = "Page not found.";}
          /* Remove the attribute, and call this function once more: */
          elmnt.removeAttribute("w3-include-html");
          includeHTML();
        }
      }
      xhttp.open("GET", file, true);
      xhttp.send();
      /* Exit the function: */
      return;
    }
  }
}
</script>

""" + self.std_header_html + """
</head>
<body>
    <div data-role="page" id="page-index">
        <div data-role="header" data-theme="c" data-position="fixed">
            <h1>BookIt</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h2 class="bi-text-center">Welcome!</h2>
            <p class="bi-top-margin-1-5"><b>Existing Users</b></p>
            <a href="#page-signin" class="ui-btn ui-btn-b ui-corner-all">Sign In</a>
            <p class="bi-top-margin-1-5"><b>Don't have an account?</b></p>
            <a href="#page-signup" class="ui-btn ui-btn-b ui-corner-all">Sign Up</a>
            <p></p>
        </div><!-- /content -->
    </div><!-- /page -->
    <div data-role="page" id="page-signup">
        <div class="bi-header" data-role="header" data-theme="c" data-position="fixed">
            <a href="#page-index" data-icon="home" data-iconpos="notext" data-transition="slide" data-direction="reverse"></a>
            <h1>Sign Up</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <div id="ctn-err" class="bi-invisible"></div>
            <div class="ui-field-contain">
                <select name="select-custom-22" id="cbo-cong" data-native-menu="false">
                    <option>Select Congregation...</option>
""" + self.cong_html + """
                    </select>
            </div>
            <div class="controlgroup" data-role="controlgroup" data-type="horizontal" name="rc-gender" id="rc-gender" style="margin-top: 0px;">
                    <input type="radio" name="rc-gender-ckb" id="rc-gender-male" value="male">
                    <label for="rc-gender-male">Male</label>
                    <input type="radio" name="rc-gender-ckb" id="rc-gender-female" value="female">
                    <label for="rc-gender-female">Female</label>
            </div>
            <label for="ckb-bap">Baptised</label>
            <input type="checkbox" name="ckb-bap" id="ckb-bap">
            <label for="txt-first-name">First Name</label>
            <input type="text" name="txt-first-name" id="txt-first-name" value="">
            <label for="txt-last-name">Last Name</label>
            <input type="text" name="txt-last-name" id="txt-last-name" value="">
            <label for="txt-email-address">Email Address</label>
            <input type="text" name="txt-email-address" id="txt-email-address" value="">
            <label for="txt-password">Password</label>
            <input type="password" name="txt-password" id="txt-password" value="">
            <label for="txt-password-confirm">Confirm Password</label>
            <input type="password" name="txt-password-confirm" id="txt-password-confirm" value="">
            <!-- <a href="#dlg-sign-up-sent" data-rel="popup" data-transition="pop" data-position-to="window" id="btn-submit" class="ui-btn ui-btn-b ui-corner-all bi-top-margin-1-5">Submit</a> -->
            <button id="btn-submit" class="ui-btn ui-btn-b ui-corner-all bi-top-margin-1-5">Submit</button>
            <div data-role="popup" id="dlg-sign-up-sent" data-dismissible="false" style="max-width:400px;">
                <div data-role="header">
                    <h1>Almost done...</h1>
                </div>
                <div role="main" class="ui-content">
                    <h3>Confirm Your Email Address</h3>
                    <p>We sent you an email with instructions on how to confirm your email address. Please check your inbox and follow the instructions in the email.</p>
                    <div class="bi-text-center"><a href="/" class="ui-btn ui-corner-all ui-shadow ui-btn-b bi-top-margin-1-5">OK</a></div>

                </div>
            </div>
        </div><!-- /content -->
    </div><!-- /page -->
    <div data-role="page" id="page-signup-succeeded">
        <div data-role="header" data-theme="c">
            <h1>Book It</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h2 class="bi-text-center">Registration Succeeded</h2>
            <p class="bi-top-margin-1-5">Congratulations!  You are now registered with HandsUp.</p>
            <a href="#page-signin" class="ui-btn ui-btn-b ui-corner-all">Sign In</a>
            <p></p>
        </div><!-- /content -->
    </div><!-- /page -->
    <div data-role="page" id="page-signin">
        <div data-role="header" data-theme="c" data-position="fixed">
            <a href="#page-index" data-icon="home" data-iconpos="notext" data-transition="slide" data-direction="reverse"></a>
            <h1>Sign In</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
            <h3>Sign In</h3>
            <div id="ctn-err" class="bi-invisible"></div>
            <label for="txt-email-address">Email Address</label>
            <input type="text" name="txt-email-address" id="txt-email-address" value="">
            <label for="txt-password">Password</label>
            <input type="password" name="txt-password" id="txt-password" value="">
            <a href="#dlg-invalid-credentials" data-rel="popup" data-transition="pop" data-position-to="window" id="btn-submit" class="ui-btn ui-btn-b ui-corner-all bi-top-margin-1-5">Submit</a>
            <p class="bi-top-margin-1-5"><a href="#begin-password-reset-page">Can't access your account?</a></p>
        </div><!-- /content -->
    </div><!-- /page -->
    <div data-role="page" id="apps">
        <div data-role="header" data-theme="c" data-position="fixed">
            <a href="#page-index" data-icon="home" data-iconpos="notext" data-transition="slide" data-direction="reverse"></a>
            <h1>Hands Up</h1>
             <a href="#page-signin" data-role="button" id="button_logout" data-icon="false" data-iconpos="false">logout</a>
        </div><!-- /header -->
        <div role="main" class="ui-content">
{{APP_HTML}}

        </div><!-- /content -->
    </div><!== /page -->
    <div data-role="page" id="page-main-menu">
        <div data-role="header" data-theme="c">
            <h1>Book It</h1>
        </div><!-- /header -->
        <div role="main" class="ui-content">
        </div><!-- /content -->
    </div><!-- /page -->
<div data-role="page" id="page-bookings">
    <div data-role="header" data-theme="c">
        <h1>Book It</h1>
    </div><!-- /header -->
    <div role="main" id="bookings-list-ctn" class="ui-content">
        <!-- The hard-coded list used to be here -->
    </div><!-- /content -->
</div><!-- /page -->

    <script src="js/api-messages.js"></script>
    <script src="js/settings.js"></script>
    <script src="js/signup-controller.js"></script>
    <script src="js/signin-controller.js"></script>
    <script type="text/javascript" src="js/index.js"></script>
</body>
</html>
"""
            self.index_html = self.index_html.replace(
                '{{APP_HTML}}', FRIEND_HANDUP_HTML)

        return web.Response(text=self.index_html, content_type='text/html')

    async def handler_app_min_css(self, request):
        return web.Response(text=self.app_css, content_type='text/css')

    async def post_signup(self, request):
        resp = {'success': True, 'extras': {'msg': None}}
        s = json.dumps(resp)
        print("got post", s)
        return web.json_response(resp)

    async def post_msg(self, request):
        pname = request.match_info['pname']
        print(pname)
        db = request.app['db']

        def json_resp(res=None):
            ret = {
                'success': True} if res is None else {
                'success': False,
                'extras': {
                    'msg': res}}
            print(ret)
            return web.json_response(ret)

        if pname == 'sign-up':
            data = await request.post()
            print(data)
            try:
                async with db.execute('''select 1 from user where email = ?''', (data['email'],)) as cur:
                    row = await cur.fetchone()
                    if row is not None:
                        print("email already registered", data['email'])
                        return json_resp(self.EMAIL_ALREADY_EXISTS)
                async with db.execute('''insert into user (email,firstname,lastname,passwordhash) values (?,?,?,?)''',
                                      (data['email'], data['firstName'], data['lastName'], data['password'])):
                    await db.commit()

                    return json_resp()
            except Exception:
                print("db error", sys.exc_info())
                return json_resp(self.DB_ERROR)
        elif pname == 'sign-in':
            data = await request.post()
            pw, pwsalt, name, email, firstname, lastname, roles = None, None, None, None, None, None, None
            try:
                async with db.execute('''select passwordhash,passwordsalt,name,email,firstname,lastname,roles from user where email = ?''', (data['email'],)) as cur:
                    row = await cur.fetchone()
                    if row is not None:
                        pw, pwsalt, name, email, firstname, lastname, roles = row
            except Exception:
                print("db error", sys.exc_info())
                return json_resp(self.DB_ERROR)
            print("post of sign-in")
            if pw is None:
                return json_resp(self.EMAIL_NOT_FOUND)
            print("post of sign-in")
            if pwsalt is not None:
                pass  # add salt into password before comparing.
            if pw != data['password']:
                print(data['email'], pw, data['password'])
                return json_resp(self.INVALID_PWD)
            # Login Session.
            redirect_response = web.HTTPSeeOther('/#apps')
            session = await get_session(request)
            if name is None and roles is not None:
                name = firstname.trim() + ' ' + lastname.trim()
            session['email'], session['name'] = email, name
            await remember(request, redirect_response, data['email'])
            print("post of sign-in3")
            raise redirect_response

    async def authorized_userid(self, identity):
        """Retrieve authorized user id.
        Return the user_id of the user identified by the identity
        or 'None' if no user exists related to the identity.
        """
        async with aiosqlite.connect(self.dbname) as db:
            try:
                async with db.execute('''select roles from user where email = ? and active and roles is not null''', (identity,)) as cur:
                    row = await cur.fetchone()
                    if row is None:
                        return None

                    return identity
            except Exception:
                print(
                    'db_error in authorized_userid',
                    identity,
                    sys.exc_info())
                return None

    async def permits(self, identity, permission, context):
        """Check user permissions.
        Return True if the identity is allowed the permission
        in the current context, else return False.
        """

        session, db = context
        cong_id = self.cong_id
        roles = session['roles']
        if roles is not None:
            roles = roles.split(',')
        if 'admin' in roles:
            return True
        if (self.cong_id is None or session['cong_id']
                == self.cong_id) and 'handsup' in roles:
            return True
        return False

    async def handle_javascript(self, request):
        script = request.match_info['pname']
        print("script>>", script)
        if script == 'settings.js':
            x = """
var HandsUp = HandsUp || {};
HandsUp.Settings = HandsUp.Settings || {};
HandsUp.Settings.signUpUrl = location.protocol + "//"+location.host+"/post/sign-up";
HandsUp.Settings.signInUrl = location.protocol + "//"+location.host+"/post/sign-in";
HandsUp.Settings.handUpUrl = location.protocol + "//"+location.host+"/friend_handup/post";

"""
        elif script == 'api-messages.js':
            x = """
var BookIt = BookIt || {};
HandsUp.ApiMessages = HandsUp.ApiMessages || {};
"""

            def add(var, val):
                return "HandsUp.ApiMessages." + var + '=' + str(val) + ";\n"
            x += add('EMAIL_NOT_FOUND', self.EMAIL_NOT_FOUND)
            x += add('INVALID_PWD', self.INVALID_PWD)
            x += add('DB_ERROR', self.DB_ERROR)
            x += add('NOT_FOUND', self.NOT_FOUND)
            x += add('EMAIL_ALREADY_EXISTS', self.EMAIL_ALREADY_EXISTS)

            print(x)
        elif script == 'index.js':
            x = """
var BookIt = BookIt || {};

// Begin boilerplate code generated with Cordova project.

var app = {
    // Application Constructor
    initialize: function () {
        this.bindEvents();
    },
    // Bind Event Listeners
    //
    // Bind any events that are required on startup. Common events are:
    // 'load', 'deviceready', 'offline', and 'online'.
    bindEvents: function () {
        document.addEventListener('deviceready', this.onDeviceReady, false);
    },
    // deviceready Event Handler
    //
    // The scope of 'this' is the event. In order to call the 'receivedEvent'
    // function, we must explicitly call 'app.receivedEvent(...);'
    onDeviceReady: function () {
        app.receivedEvent('deviceready');
    },
    // Update DOM on a Received Event
    receivedEvent: function (id) {

    }
};

app.initialize();

// End boilerplate code.

$(document).on("mobileinit", function (event, ui) {
    $.mobile.defaultPageTransition = "slide";
});

app.signUpController = new HandsUp.SignUpController();
app.signInController = new HandsUp.SignInController();

$(document).on("pagecontainerbeforeshow", function (event, ui) {
    if (typeof ui.toPage == "object") {
        switch (ui.toPage.attr("id")) {
            case "page-signup":
                // Reset the signup form.
                app.signUpController.resetSignUpForm();
                break;
            case "page-signin":
                // Reset signin form.
                app.signInController.resetSignInForm();
                break;
       }
    }
});


$(document).delegate("#page-signup", "pagebeforecreate", function () {

    app.signUpController.init();

    app.signUpController.$btnSubmit.off("tap").on("tap", function () {
        app.signUpController.onSignUpCommand();
    });
});

$(document).delegate("#page-signin", "pagebeforecreate", function () {

    app.signInController.init();

    app.signInController.$btnSubmit.off("tap").on("tap", function () {
        app.signInController.onSignInCommand();
    });
});

"""
        elif script == 'signin-controller.js':
            x = """
var BookIt = BookIt || {};

HandsUp.SignInController = function () {

    this.$signInPage = null;
    this.bookingsPageId = null;
    this.$btnSubmit = null;
    this.$ctnErr = null;
    this.$txtEmailAddress = null;
    this.$txtPassword = null;
    this.$chkKeepSignedIn = null;
};

HandsUp.SignInController.prototype.init = function () {
    this.$signInPage = $("#page-signin");
    this.bookingsPageId = "#page-bookings";
    this.$btnSubmit = $("#btn-submit", this.$signInPage);
    this.$ctnErr = $("#ctn-err", this.$signInPage);
    this.$txtEmailAddress = $("#txt-email-address", this.$signInPage);
    this.$txtPassword = $("#txt-password", this.$signInPage);
    this.$chkKeepSignedIn = $("#chk-keep-signed-in", this.$signInPage);
};

HandsUp.SignInController.prototype.emailAddressIsValid = function (email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

HandsUp.SignInController.prototype.resetSignInForm = function () {

    var invisibleStyle = "bi-invisible",
        invalidInputStyle = "bi-invalid-input";

    this.$ctnErr.html("");
    this.$ctnErr.removeClass().addClass(invisibleStyle);
    this.$txtEmailAddress.removeClass(invalidInputStyle);
    this.$txtPassword.removeClass(invalidInputStyle);
    this.$txtEmailAddress.val("");
    this.$txtPassword.val("");
    this.$chkKeepSignedIn.prop("checked", false);

};

HandsUp.SignInController.prototype.onSignInCommand = function () {

    var me = this,
        emailAddress = me.$txtEmailAddress.val().trim(),
        password = me.$txtPassword.val().trim(),
        invalidInput = false,
        invisibleStyle = "bi-invisible",
        invalidInputStyle = "bi-invalid-input";

    // Reset styles.
    me.$ctnErr.removeClass().addClass(invisibleStyle);
    me.$txtEmailAddress.removeClass(invalidInputStyle);
    me.$txtPassword.removeClass(invalidInputStyle);

    // Flag each invalid field.
    if (emailAddress.length === 0) {
        me.$txtEmailAddress.addClass(invalidInputStyle);
        invalidInput = true;
    }
    if (password.length === 0) {
        me.$txtPassword.addClass(invalidInputStyle);
        invalidInput = true;
    }

    // Make sure that all the required fields have values.
    if (invalidInput) {
        me.$ctnErr.html("<p>Please enter all the required fields.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        return;
    }

    if (!me.emailAddressIsValid(emailAddress)) {
        me.$ctnErr.html("<p>Please enter a valid email address.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        me.$txtEmailAddress.addClass(invalidInputStyle);
        return;
    }

    $.mobile.loading("show");

    $.ajax({
        type: 'POST',
        url: HandsUp.Settings.signInUrl,
        data: "email=" + emailAddress + "&password=" + \
         CryptoJS.SHA512(emailAddress.trim().toLowerCase()+password),
        dataType: "json",
        success: function (resp) {

            $.mobile.loading("hide");
            if (resp.redirect) {
                // data.redirect contains the string URL to redirect to
                window.location.href = data.redirect;
            } else {
                if (resp.extras.msg) {
                    switch (resp.extras.msg) {
                        case HandsUp.ApiMessages.DB_ERROR:
                        // TODO: Use a friendlier error message below.
                            me.$ctnErr.html("<p>Oops! BookIt had a problem and could not log you on.  Please try again in a few minutes.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            break;
                        case HandsUp.ApiMessages.INVALID_PWD:
                        case HandsUp.ApiMessages.EMAIL_NOT_FOUND:
                            me.$ctnErr.html("<p>You entered a wrong username"+\
                            " or password.  Please try again.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            me.$txtEmailAddress.addClass(invalidInputStyle);
                            break;
                    }
                }
            }
        },
        error: function (e) {
            $.mobile.loading("hide");
            console.log(e.message);
            // TODO: Use a friendlier error message below.
            me.$ctnErr.html("<p>Oops! BookIt had a problem and could not log"+\
            " you on.  Please try again in a few minutes.</p>");
            me.$ctnErr.addClass("bi-ctn-err").slideDown();
        },
        error:  function (jqXHR, timeout, message) {
            var contentType = jqXHR.getResponseHeader("Content-Type");
            $.mobile.loading("hide");
            if (jqXHR.status === 200 && \
            contentType.toLowerCase().indexOf("text/html") >= 0) {
                // assume that our login has expired - reload our current page
                // window.location.reload();
                window.location.href = '/#apps'
            }
            else
            {
                me.$ctnErr.html("<p>Oops! BookIt had a problem and could not log you on.  Please try again in a few minutes.</p>");
                me.$ctnErr.addClass("bi-ctn-err").slideDown();

            }
        },W
    });
};
"""
        elif script == 'bookings-controller.js':
            x = """
"""
        elif script == 'signup-controller.js':
            x = """
var BookIt = BookIt || {};

HandsUp.SignUpController = function () {

    this.$signUpPage = null;
    this.$btnSubmit = null;
    this.$ctnErr = null;
    this.$txtFirstName = null;
    this.$txtLastName = null;
    this.$txtEmailAddress = null;
    this.$txtPassword = null;
    this.$txtPasswordConfirm = null;
    this.$rbtnGender = null;
    this.$cboCong = null;
    this.$ckbBap = null;
};

HandsUp.SignUpController.prototype.init = function () {
    this.$signUpPage = $("#page-signup");
    this.$btnSubmit = $("#btn-submit", this.$signUpPage);
    this.$ctnErr = $("#ctn-err", this.$signUpPage);
    this.$txtFirstName = $("#txt-first-name", this.$signUpPage);
    this.$txtLastName = $("#txt-last-name", this.$signUpPage);
    this.$txtEmailAddress = $("#txt-email-address", this.$signUpPage);
    this.$txtPassword = $("#txt-password", this.$signUpPage);
    this.$txtPasswordConfirm = $("#txt-password-confirm", this.$signUpPage);
    this.$cboCong =      $("#cbo-cong", this.$signUpPage);
    this.$ckbBap =      $("#ckb-bap", this.$signUpPage);

};

HandsUp.SignUpController.prototype.passwordsMatch = function (password, passwordConfirm) {
    return password === passwordConfirm;
};

HandsUp.SignUpController.prototype.passwordIsComplex = function (password) {
    // TODO: implement complex password rules here.  There should be similar rule on the server side.
    return true;
};

HandsUp.SignUpController.prototype.emailAddressIsValid = function (email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

HandsUp.SignUpController.prototype.resetSignUpForm = function () {

    var invisibleStyle = "bi-invisible",
        invalidInputStyle = "bi-invalid-input";

    this.$ctnErr.html("");
    this.$ctnErr.removeClass().addClass(invisibleStyle);
    this.$txtFirstName.removeClass(invalidInputStyle);
    this.$txtLastName.removeClass(invalidInputStyle);
    this.$txtEmailAddress.removeClass(invalidInputStyle);
    this.$txtPassword.removeClass(invalidInputStyle);
    this.$txtPasswordConfirm.removeClass(invalidInputStyle);

    this.$txtFirstName.val("");
    this.$txtLastName.val("");
    this.$txtEmailAddress.val("");
    this.$txtPassword.val("");
    this.$txtPasswordConfirm.val("");

};

HandsUp.SignUpController.prototype.onSignUpCommand = function () {
    this.$rbtnGender = $("#rc-gender :radio:checked", this.$signUpPage);

    var me = this,
        firstName = me.$txtFirstName.val().trim(),
        lastName = me.$txtLastName.val().trim(),
        emailAddress = me.$txtEmailAddress.val().trim(),
        password = me.$txtPassword.val().trim(),
        passwordConfirm = me.$txtPasswordConfirm.val().trim(),
        invalidInput = false,
        invisibleStyle = "bi-invisible",
        gender = me.$rbtnGender.val(),
        cong = me.$cboCong.val(),
        bap = me.$ckbBap.val() === 'on',
        invalidInputStyle = "bi-invalid-input";

    // Reset styles.
    me.$ctnErr.removeClass().addClass(invisibleStyle);
    me.$txtFirstName.removeClass(invalidInputStyle);
    me.$txtLastName.removeClass(invalidInputStyle);
    me.$txtEmailAddress.removeClass(invalidInputStyle);
    me.$txtPassword.removeClass(invalidInputStyle);
    me.$txtPasswordConfirm.removeClass(invalidInputStyle);

    // Flag each invalid field.
    if (firstName.length === 0) {
        me.$txtFirstName.addClass(invalidInputStyle);
        invalidInput = true;
    }
    if (lastName.length === 0) {
        me.$txtLastName.addClass(invalidInputStyle);
        invalidInput = true;
    }
    if (emailAddress.length === 0) {
        me.$txtEmailAddress.addClass(invalidInputStyle);
        invalidInput = true;
    }
    if (password.length === 0) {
        me.$txtPassword.addClass(invalidInputStyle);
        invalidInput = true;
    }
    if (passwordConfirm.length === 0) {
        me.$txtPasswordConfirm.addClass(invalidInputStyle);
        invalidInput = true;
    }

    // Make sure that all the required fields have values.
    if (invalidInput) {
        me.$ctnErr.html("<p>Please enter all the required fields.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        return;
    }

    if (!me.emailAddressIsValid(emailAddress)) {
        me.$ctnErr.html("<p>Please enter a valid email address.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        me.$txtEmailAddress.addClass(invalidInputStyle);
        return;
    }

    if (!me.passwordsMatch(password, passwordConfirm)) {
        me.$ctnErr.html("<p>Your passwords don't match.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        me.$txtPassword.addClass(invalidInputStyle);
        me.$txtPasswordConfirm.addClass(invalidInputStyle);
        return;
    }

    if (!me.passwordIsComplex(password)) {
        // TODO: Use error message to explain password rules.
        me.$ctnErr.html("<p>Your password is very easy to guess. Please try a more complex password.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        me.$txtPassword.addClass(invalidInputStyle);
        me.$txtPasswordConfirm.addClass(invalidInputStyle);
        return;
    }
    data = "email=" + emailAddress + "&firstName=" + firstName + "&lastName=" + lastName
    data+= "&cong="+cong + "&bap=" + (bap?1:0) + "&gender="+gender
    data+= "&password=" + CryptoJS.SHA512(emailAddress.trim().toLowerCase()+password)

    $.ajax({
        type: 'POST',
        url: HandsUp.Settings.signUpUrl,
        data: data,
        success: function (resp) {

            if (resp.success === true) {
                $( "#dlg-sign-up-sent" ).popup( "open" )
                // $.mobile.navigate("#dlg-sign-up-sent");
                return;
            } else {
                if (resp.extras.msg) {
                    switch (parseInt(resp.extras.msg)) {
                        case HandsUp.ApiMessages.DB_ERROR:
                        case HandsUp.ApiMessages.COULD_NOT_CREATE_USER:
                            // TODO: Use a friendlier error message below.
                            me.$ctnErr.html("<p>Oops! BookIt had a problem and could not register you.  Please try again in a few minutes.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            break;
                        case HandsUp.ApiMessages.EMAIL_ALREADY_EXISTS:
                            me.$ctnErr.html("<p>The email address that you provided is already registered.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            me.$txtEmailAddress.addClass(invalidInputStyle);
                            break;
                        default:
                            me.$ctnErr.html("<p>Unknown Error "+HandsUp.ApiMessages.EMAIL_ALREADY_EXIST+".</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                    }
                }
            }
        },
        error: function (e) {
            console.log(e.message);
            // TODO: Use a friendlier error message below.
            me.$ctnErr.html("<p>Oops! BookIt had a problem and could not register you.  Please try again in a few minutes.</p>");
            me.$ctnErr.addClass("bi-ctn-err").slideDown();
        }
    });
};
"""
        else:
            raise NameError(request.rel_url.path)

        return web.Response(text=x, content_type='text/javascript')

    async def handle_khapp_css(self, request):
        x = """
"""
        return web.Response(text=x, content_type='text/css')

    async def handler_signup_succeeded(self, request):
        return web.Response(text=self.signup_succeeded_html,
                            content_type='text/html')

    async def load_cong_html(self):
        print("load_cong_html")
        async with aiosqlite.connect(self.dbname) as db:
            res = ''
            try:
                async with db.execute('SELECT id,name FROM cong') as cursor:
                    async for row in cursor:
                        res += '    <option value="{}">{}</option>'.format(
                            row[0], row[1]) + "\n"
                        print(row[0], row[1])
            except Exception:
                print("db error", sys.exc_info())
                raise
            self.cong_html = res

    async def sse_handsup(self, request):
        addnames, remnames, names = [], [], []

        async with sse_response(request) as resp:
            while True:
                async with self.cond:
                    while True:
                        addnames = (list(set(self.names) - set(names)))
                        remnames = (list(set(names) - set(self.names)))
                        if len(addnames) > 0 or len(remnames) > 0:
                            break
                        await self.cond.wait()
                    names = self.names.copy()
                for name in remnames:
                    await resp.send("-" + name)
                for name in addnames:
                    await resp.send("+" + name)

    async def get_loggedin_session(self, request):
        if await is_anonymous(request):
            raise web.HTTPSeeOther('#page-signin')
        db = request.app['db']
        session = await get_session(request)

        async with db.execute('''select name,roles,cong_id from user where email = ?''', (session['email'],)) as cur:
            row = await cur.fetchone()
            if row is None:
                self.logout(request)  # This raises an exception
            name, session['roles'], session['cong_id'] = row
            if name is None:  # admin did not setup name yet.
                raise web.HTTPSeeOther('#admin-action-required')

            if 'name' in session and session['name'] != name:
                session['old_name'] = session['name']
                session['name'] = name
                session['name_change'] = True
            elif 'name_change' in session and session['name_change']:
                del session['name_change']
                del session['old_name']

        return session

    async def logout(self, request):
        redirect_response = web.HTTPFound('#page-signin')
        await forget(request, redirect_response)
        raise redirect_response

    async def handler(self, request):
        if request.path == '/display_handsup':
            return web.Response(
                text=DISPLAY_HANDS_UP_HTML,
                content_type='text/html')

        if await is_anonymous(request):
            raise web.HTTPFound('/#page-signin')

        if request.path == '/friend_handup':
            print("got to apps")
#            session = await self.get_loggedin_session(request)
#            print("friend handup")
# await check_permission(request,'handsup',(session,request.app['db'],))

            return web.Response(
                text=FRIEND_HANDUP_HTML,
                content_type='text/html')

        if request.path == '/friend_handup/post':
            if request.body_exists:
                msg = await request.text()
                mode = msg[:1]
                session = await self.get_loggedin_session(request)
                name = session['name']
                async with self.cond:
                    print(mode, name)
                    if mode == '+' and name not in self.names:
                        self.names.append(name)
                    if mode == '-':
                        if 'name_change' in session:
                            name = session['old_name']
                        while name in self.names:
                            self.names.remove(name)

                    self.cond.notify_all()
            return web.json_response({})


if s.query(Profile).first() is None:
    cfg = Profile()
    Handler(cfg).create_schema()
    print(cfg)
    s.add_all([cfg])
    s.commit()
    print("exiting after creation of db. re-run to run website.")
    sys.exit(0)

cfg = s.query(Profile).filter_by(name=profile_name).one_or_none()

hdl = Handler(cfg)

tasks = []


async def start_srvs(_cfg):
    cfg = _cfg

    ssl_cert, ssl_key = None, None

    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key)
    middleware = session_middleware(EncryptedCookieStorage(secret_key))
    app1 = web.Application(middlewares=[middleware])
    std_routes = [
        web.get('/', hdl.handler_root),
        web.get('/#apps', hdl.handler_root),
        web.get('/css/app.css', hdl.handler_app_min_css),
        web.get('/signup-succeeded.html', hdl.handler_signup_succeeded),
        web.get('/js/{pname}', hdl.handle_javascript),
        web.post('/post/{pname}', hdl.post_msg),
        web.get('/css/themes/1/khapp.min.css', hdl.handle_khapp_css),
    ]
    app1.add_routes(std_routes)
    app1.router.add_get('/friend_handup', hdl.handler)
    app1.router.add_post('/friend_handup/post', hdl.handler)
    app1['httpd_listen_ip'] = cfg.public_listen_ip
    app1['httpd_listen_port'] = cfg.public_port
    app1['httpd_ip'] = cfg.private_listen_ip
    app1['httpd_port'] = cfg.private_port
    app1['use_ssl'] = ssl_cert is not None
    db = await aiosqlite.connect(hdl.dbname)
    print("db connect request")
    app1['db'] = db
    runner = web.AppRunner(app1)
    await runner.setup()

    ssl_context = None

    if cfg.public_ssl is not None:
        p = cfg.public_ssl
        ssl_cert = cfg.public_ssl[0].certif_str
        ssl_key = cfg.public_ssl[0].key_str
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(p.certif_str, str(ssl_key))

    site = web.TCPSite(
        runner,
        cfg.public_listen_ip,
        cfg.public_port,
        ssl_context=ssl_context)

    print("first tcp site")
    await site.start()
    _, port = runner.addresses[0]
    print(port)
    igd = IGdMgr(local_ip=None, local_port=port, local_bind_ip='127.0.0.1',
                 ext_port=8080, protocol='TCP')
    loop = asyncio.get_event_loop()
    loop.create_task(igd.run())

    middleware = session_middleware(EncryptedCookieStorage(secret_key))
    app2 = web.Application(middlewares=[middleware])
    app2.add_routes(std_routes)

    app2['httpd_listen_ip'] = cfg.private_listen_ip
    app2['httpd_listen_port'] = cfg.private_port
    # for right now
    app2['httpd_ip'] = cfg.private_listen_ip
    app2['httpd_port'] = cfg.private_port

    app2.router.add_get('/friend_handup', hdl.handler)
    app2.router.add_post('/friend_handup/post', hdl.handler)
    app2.router.add_get('/display_handsup', hdl.handler)
    app2.router.add_get('/sse_handsup', hdl.sse_handsup)
    app2['use_ssl'] = False
    app2['db'] = db

    runner = web.AppRunner(app2)
    await runner.setup()
    site = web.TCPSite(runner, cfg.private_listen_ip, cfg.private_port)
    print("second tcp site")
    await site.start()
    policy = SessionIdentityPolicy()
    setup_security(app1, policy, hdl)
    policy = SessionIdentityPolicy()
    setup_security(app2, policy, hdl)


async def handle_process(process):
    line = None
    try:
        async for line in process.stdin:
            line = line.rstrip('\n')
    finally:
        pass
    print(line)


class KuttItShortner:
    baseurl = 'https://kutt.it'

    def __init__(self, apikey, session=None):
        self.headers, self.client = {'X-API-Key': apikey}, session

    async def delete_customurl(self, _id, session=None, domain=None):
        data = {'id': _id} if domain is None else {'id': _id, 'domain': domain}

        return await self._cli_post(self.baseurl + '/api/url/delete_customurl',
                                    session, data)

    async def submiturl(self, _id, target, session=None, reuse=False,
                        password=None):
        data = {'customurl': _id, 'target': target, 'reuse': reuse}
        if password is not None:
            data.update({'password': password})

        return await self._cli_post(self.baseurl + '/api/url/submit',
                                    session, data)

    async def _cli_post(self, url, cli, data):

        async def _cli_post2(url, session, hdrs, data):
            async with session.post(url, headers=hdrs, json=data) as resp:
                return await resp.json()

        if cli is None or self.client is None:
            async with aiohttp.ClientSession() as session:
                return await _cli_post2(url, session, self.headers, data)

        return await _cli_post2(url, self.client, self.headers, data)


async def stop_website():
    #    await runner.cleanup()
    #    loop = asyncio.get_event_loop()
    await loop.shutdown_asyncgens()

loop = asyncio.get_event_loop()
# loop.run_until_complete(run_client(cfg))
loop.create_task(start_srvs(cfg))
try:
    loop.run_forever()
finally:
    pass
