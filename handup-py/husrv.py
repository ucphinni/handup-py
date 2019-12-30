from urllib.parse import urlparse
import asyncio
import json
import os
import sqlite3
import sys

from aiohttp import web
from aiohttp_security import check_permission, \
    is_anonymous, remember, forget, \
    setup as setup_security, SessionIdentityPolicy
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aiohttp_session import SimpleCookieStorage, session_middleware
from aioyagmail import AIOSMTP
import aiosqlite


oauth2_file = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop',
                           "client_secret.json")
""" This class uses the asynch gmail in order to respond the registration process of the login registration of the user.
    It is assumed that the user is from the kingdom hall. The sound operator is responsibible for accepting the user into the sysgtem
    and making sure that the name that is displayed to the conductor on the third screen is short and meaningful enough.

"""


class WebLogin(AbstractAuthorizationPolicy):
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
            <p class="mc-top-margin-1-5">Congratulations!  You are now registered with BookIt.</p>
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
    DROP TABLE IF EXISTS Cong;
    DROP TABLE IF EXISTS User;

    CREATE TABLE User
    (
    id    integer primary key autoincrement,
    email text unique,
    prefix text ,
    sex char(1),
    is_baptized int,
    firstname text,
    lastname text,
    name_given text,
    emaillink text,
    emaillink_timeout text,
    passwordhash text,
    passwordsalt text,
    permission text,
    cong_id int,

    active int,
    FOREIGN KEY(cong_id) REFERENCES Cong(id)
    );

    CREATE TABLE Cong
    (
        id    integer primary key autoincrement,
        name  text unique
    );
    INSERT INTO CONG (name) VALUES ('East WBoro');
    INSERT INTO CONG (name) VALUES ('West WBoro');
    INSERT INTO CONG (name) VALUES ('North WBoro');
    INSERT INTO CONG (name) VALUES ('Lumberton');
    INSERT INTO User (email,sex,is_baptized,firstname,lastname,name_given,passwordhash,permission,cong_id)
    VALUES('ucphinni@gmail.com','M',1,'Cote','Phinnizee','C Phinnizee',
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

    def __init__(self):
        self.dbname = 'test.db'
        self.serversalt = None
        self.cong_html = None
        self.index_html = None

    def validate_password(self, passwordhash,
                          passwordsalt, password, serversalt):
        return True

    async def do_login(self, email, password):
        row = None
        async with aiosqlite.connect(self.dbname) as db:
            try:
                async with db.execute('''select passwordhash,passwordsalt,firstname,
                          lastname from user where email = ?''', (email,)) as cur:
                    row = await cur.fetchone()
            except Exception:
                return (self.DB_ERROR,)
        if row is None:
            return (self.EMAIL_NOT_FOUND, None)
        if self.validate_password(row[0], row[1], password, None):
            return (self.LOGIN_SUCCESS, (email, row[2], row[3]))
        return (self.INVALID_PWD, None)

    async def do_register(self, email, firstname, lastname):
        async with aiosqlite.connect(self.dbname) as db:
            try:
                async with db.execute('''select 1 from user where email = ?''', (email,)) as cur:
                    row = await cur.fetchone()
                    if row is not None:
                        return self.EMAIL_ALREADY_EXISTS
                async with db.execute('''insert into user (email,firstname,lastname) values (?,?,?)''', email, firstname, lastname):
                    return self.LOGIN_SUCCESS if cur.rowcount == 1 else self.COULD_NOT_CREATE_USER
            except Exception:
                return self.DB_ERROR

    async def do_resetpassword(self):
        pass

    async def create_schema(self):
        async with aiosqlite.connect(self.dbname) as conn:
            await conn.executescript(self.schema_sql)

    async def send_registration_link(self, email_to):
        # walks you through oauth2 process if no file at this location
        async with AIOSMTP('ucphinni', oauth2_file=oauth2_file) as yag:
            await yag.send(to=email_to, subject="Welcome to KHServer",
                           contents=None)

    async def send_confirmation(self, email_to):
        # walks you through oauth2 process if no file at this location
        async with AIOSMTP('ucphinni', oauth2_file=oauth2_file) as yag:
            await yag.send(to=email_to, subject="Welcome to KHServer",
                           contents=None)

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

""" + self.std_header_html + """
<style>
.grids {
    border-style: solid;
    border-width: 5px;
}
.grids div {
    display: table;
    height: 153px;
}
.grids div > p {
    display: table-cell;
    vertical-align: middle;
    text-align: center;
}
</style>
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
            <p class="bi-top-margin-1-5">Congratulations!  You are now registered with BookIt.</p>
            <a href="#page-signin" class="ui-btn ui-btn-b ui-corner-all">Sign In</a>
            <p></p>
        </div><!-- /content -->
    </div><!-- /page -->
    <div data-role="page" id="page-handup">
        <div data-role="header" data-theme="c" data-position="fixed">
            <a href="#page-index" data-icon="home" data-iconpos="notext" data-transition="slide" data-direction="reverse"></a>
            <h1>Hands Up</h1>
             <a href="#page-signin" data-role="button" id="button_logout" data-icon="false" data-iconpos="false">logout</a>
        </div><!-- /header -->
        <div role="main" class="ui-content">

        </div><!-- /content -->
    </div><!== /page -->
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

        return web.Response(text=self.index_html, content_type='text/html')

    async def handler_apps(self, request):
        return web.Response(text='Logged in', content_type='text/html')

    async def handler_signup(self, request):
        return web.Response(text=self.signup_html, content_type='text/html')

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
            async with aiosqlite.connect(self.dbname) as db:
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
            pw, pwsalt = None, None
            async with aiosqlite.connect(self.dbname) as db:
                try:
                    async with db.execute('''select passwordhash,passwordsalt from user where email = ?''', (data['email'],)) as cur:
                        row = await cur.fetchone()
                        if row is not None:
                            pw, pwsalt = row
                except Exception:
                    print("db error", sys.exc_info())
                    return json_resp(self.DB_ERROR)
            if pw is None:
                return json_resp(self.EMAIL_NOT_FOUND)
            if pwsalt is not None:
                pass  # add salt into password before comparing.
            if pw != data['password']:
                print(data['email'], pw, data['password'])
                return json_resp(self.INVALID_PWD)
            # Login Session.
            redirect_response = web.HTTPFound('/apps')
            await remember(request, redirect_response, data['email'])
            raise redirect_response

    async def authorized_userid(self, identity):
        """Retrieve authorized user id.
        Return the user_id of the user identified by the identity
        or 'None' if no user exists related to the identity.
        """
        async with aiosqlite.connect(self.dbname) as db:
            try:
                async with db.execute('''select permission from user where email = ? and active''', (identity,)) as cur:
                    row = await cur.fetchone()
                    if row is None:
                        return None
                    return identity
            except Exception:
                print('db_error in authorized_userid', identity)
                return None

    async def permits(self, identity, permission, context=None):
        """Check user permissions.
        Return True if the identity is allowed the permission
        in the current context, else return False.
        """
        async with aiosqlite.connect(self.dbname) as db:
            try:
                async with db.execute('''select 1 from user u where email = ? and active and (? = 'admin' or ? in
                        (WITH split(word, str) AS (
                            -- alternatively put your query here
                            -- SELECT '', category||',' FROM categories
                            SELECT '', u.permission ||','
                            UNION ALL SELECT
                            substr(str, 0, instr(str, ',')),
                            substr(str, instr(str, ',')+1)
                            FROM split WHERE str!=''
                        ) SELECT word FROM split WHERE word!=''))
                        ''', (identity, permission, permission)) as cur:
                    row = await cur.fetchone()
                    return row is not None
            except Exception:
                print('db_error in permts', identity)
                return None

    async def handle_javascript(self, request):
        script = request.match_info['pname']
        print("script>>", script)
        if script == 'settings.js':
            x = """
var BookIt = BookIt || {};
BookIt.Settings = BookIt.Settings || {};
BookIt.Settings.signUpUrl = "http://127.0.0.1:9000/post/sign-up";
BookIt.Settings.signInUrl = "http://127.0.0.1:9000/post/sign-in";

"""
        elif script == 'api-messages.js':
            x = """
var BookIt = BookIt || {};
BookIt.ApiMessages = BookIt.ApiMessages || {};
"""

            def add(var, val):
                return "BookIt.ApiMessages." + var + '=' + str(val) + ";\n"
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

app.signUpController = new BookIt.SignUpController();
app.signInController = new BookIt.SignInController();
// app.bookingsController = new BookIt.BookingsController();

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

$(document).on("pagecontainerbeforechange", function (event, ui) {
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

$(document).delegate("#page-bookings", "pagebeforecreate", function () {

    app.bookingsController.init();

    //app.signInController.$btnRefresh.off("tap").on("tap", function () {
    //    app.bookingsController.onRefreshCommand();
    //});

});
"""
        elif script == 'signin-controller.js':
            x = """
var BookIt = BookIt || {};

BookIt.SignInController = function () {

    this.$signInPage = null;
    this.bookingsPageId = null;
    this.$btnSubmit = null;
    this.$ctnErr = null;
    this.$txtEmailAddress = null;
    this.$txtPassword = null;
    this.$chkKeepSignedIn = null;
};

BookIt.SignInController.prototype.init = function () {
    this.$signInPage = $("#page-signin");
    this.bookingsPageId = "#page-bookings";
    this.$btnSubmit = $("#btn-submit", this.$signInPage);
    this.$ctnErr = $("#ctn-err", this.$signInPage);
    this.$txtEmailAddress = $("#txt-email-address", this.$signInPage);
    this.$txtPassword = $("#txt-password", this.$signInPage);
    this.$chkKeepSignedIn = $("#chk-keep-signed-in", this.$signInPage);
};

BookIt.SignInController.prototype.emailAddressIsValid = function (email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

BookIt.SignInController.prototype.resetSignInForm = function () {

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

BookIt.SignInController.prototype.onSignInCommand = function () {

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
        url: BookIt.Settings.signInUrl,
        data: "email=" + emailAddress + "&password=" + \
        CryptoJS.SHA512(emailAddress.trim().toLowerCase()+password),
        dataType: "json",
        success: function (resp) {

            $.mobile.loading("hide");
            if (resp.redirect) {
                // data.redirect contains the string URL to redirect to
                window.location.href = data.redirect;
/*            }
            if (resp.success === true) {
              $.mobile.navigate('/app');
                return; */
            } else {
                if (resp.extras.msg) {
                    switch (resp.extras.msg) {
                        case BookIt.ApiMessages.DB_ERROR:
                        // TODO: Use a friendlier error message below.
                            me.$ctnErr.html("<p>Oops! BookIt had a problem "+ \
                            "and could not log you on.  Please try again in "+\
                            "a few minutes.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            break;
                        case BookIt.ApiMessages.INVALID_PWD:
                        case BookIt.ApiMessages.EMAIL_NOT_FOUND:
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
                window.location.href='/apps'
            }
            else
            {
                me.$ctnErr.html("<p>Oops! BookIt had a problem and could not"+\
                " log you on.  Please try again in a few minutes.</p>");
                me.$ctnErr.addClass("bi-ctn-err").slideDown();

            }
        },
    });
};
"""
        elif script == 'bookings-controller.js':
            x = """
"""
        elif script == 'signup-controller.js':
            x = """
var BookIt = BookIt || {};

BookIt.SignUpController = function () {

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

BookIt.SignUpController.prototype.init = function () {
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

BookIt.SignUpController.prototype.passwordsMatch = \
function (password, passwordConfirm) {
    return password === passwordConfirm;
};

BookIt.SignUpController.prototype.passwordIsComplex = function (password) {
    // TODO: implement complex password rules here.  .
    return true;
};

BookIt.SignUpController.prototype.emailAddressIsValid = function (email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

BookIt.SignUpController.prototype.resetSignUpForm = function () {

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

BookIt.SignUpController.prototype.onSignUpCommand = function () {
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
        me.$ctnErr.html("<p>Your password is very easy to guess. "+\
        " Please try a more complex password.</p>");
        me.$ctnErr.addClass("bi-ctn-err").slideDown();
        me.$txtPassword.addClass(invalidInputStyle);
        me.$txtPasswordConfirm.addClass(invalidInputStyle);
        return;
    }
    data = "email=" + emailAddress + "&firstName=" + \
    firstName + "&lastName=" + lastName
    data+= "&cong="+cong + "&bap=" + (bap?1:0) + "&gender="+gender
    data+= "&password=" + \
    CryptoJS.SHA512(emailAddress.trim().toLowerCase()+password)

    $.ajax({
        type: 'POST',
        url: BookIt.Settings.signUpUrl,
        data: data,
        success: function (resp) {

            if (resp.success === true) {
                $( "#dlg-sign-up-sent" ).popup( "open" )
                // $.mobile.navigate("#dlg-sign-up-sent");
                return;
            } else {
                if (resp.extras.msg) {
                    switch (parseInt(resp.extras.msg)) {
                        case BookIt.ApiMessages.DB_ERROR:
                        case BookIt.ApiMessages.COULD_NOT_CREATE_USER:
                            // TODO: Use a friendlier error message below.
                            me.$ctnErr.html("<p>Oops! BookIt had a problem "+\
                            "and could not register you.  Please try again "+\
                            "in a few minutes.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            break;
                        case BookIt.ApiMessages.EMAIL_ALREADY_EXISTS:
                            me.$ctnErr.html("<p>The email address that you "+\
                            "provided is already registered.</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                            me.$txtEmailAddress.addClass(invalidInputStyle);
                            break;
                        default:
                            me.$ctnErr.html("<p>Unknown Error "+\
                            BookIt.ApiMessages.EMAIL_ALREADY_EXIST+".</p>");
                            me.$ctnErr.addClass("bi-ctn-err").slideDown();
                    }
                }
            }
        },
        error: function (e) {
            console.log(e.message);
            // TODO: Use a friendlier error message below.
            me.$ctnErr.html("<p>Oops! BookIt had a problem and could not "+\
            "register you.  Please try again in a few minutes.</p>");
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


hdl = WebLogin()


async def construct_app():
    await hdl.create_schema()
    middleware = session_middleware(SimpleCookieStorage())
    app = web.Application(middlewares=[middleware])

    # add the routes
    app.add_routes([
        web.get('/', hdl.handler_root),
        web.get('/apps', hdl.handler_apps),
        web.get('/css/app.css', hdl.handler_app_min_css),
        web.get('/signup-succeeded.html', hdl.handler_signup_succeeded),
        web.get('/js/{pname}', hdl.handle_javascript),
        web.post('/post/{pname}', hdl.post_msg),
        web.get('/css/themes/1/khapp.min.css', hdl.handle_khapp_css),

    ])
    policy = SessionIdentityPolicy()
    setup_security(app, policy, hdl)
    return app

loop = asyncio.get_event_loop()
web.run_app(construct_app(), port=9000)
# loop.run_until_complete(start())
